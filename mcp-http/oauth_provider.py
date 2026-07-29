"""OAuth 2.1 Authorization Server backing the MCP Streamable HTTP endpoint.

Implements mcp.server.auth.provider.OAuthAuthorizationServerProvider against
Postgres (db.py). Dynamic client registration (RFC 7591) is enabled so
claude.ai can self-register as a client on first connect. Login is a plain
email/password form (login.py) against the same web_user accounts erpclaw-web
uses — there is no third-party IdP here, the "authorize" hop just redirects
the browser to our own /login page and waits for a completed authorization
code before redirecting back to the client's redirect_uri.
"""

import json
import secrets
import time
import uuid

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

import db

ACCESS_TOKEN_TTL_SECONDS = 3600
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30
AUTH_CODE_TTL_SECONDS = 600


class ERPClawOAuthProvider(OAuthAuthorizationServerProvider):
    # -- Client registration (RFC 7591) ----------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT client_info FROM oauth_client WHERE client_id = %s", (client_id,))
            row = cur.fetchone()
            if not row:
                return None
            return OAuthClientInformationFull.model_validate_json(row["client_info"])
        finally:
            conn.close()

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO oauth_client (client_id, client_info) VALUES (%s, %s) "
                "ON CONFLICT (client_id) DO UPDATE SET client_info = EXCLUDED.client_info",
                (client_info.client_id, client_info.model_dump_json()),
            )
            conn.commit()
        finally:
            conn.close()

    # -- Authorization hop --------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        request_id = uuid.uuid4().hex
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO oauth_auth_request
                   (id, client_id, redirect_uri, redirect_uri_explicit, scopes,
                    state, code_challenge, resource)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    request_id,
                    client.client_id,
                    str(params.redirect_uri),
                    1 if params.redirect_uri_provided_explicitly else 0,
                    json.dumps(params.scopes or []),
                    params.state,
                    params.code_challenge,
                    params.resource,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return f"/mcp/login?request_id={request_id}"

    # -- Authorization code exchange -----------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM oauth_auth_code WHERE code = %s AND client_id = %s",
                (authorization_code, client.client_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            if row["expires_at"] < time.time():
                return None
            return AuthorizationCode(
                code=row["code"],
                scopes=json.loads(row["scopes"] or "[]"),
                expires_at=row["expires_at"],
                client_id=row["client_id"],
                code_challenge=row["code_challenge"],
                redirect_uri=AnyUrl(row["redirect_uri"]),
                redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
                resource=row["resource"],
            )
        finally:
            conn.close()

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT user_id FROM oauth_auth_code WHERE code = %s",
                (authorization_code.code,),
            )
            row = cur.fetchone()
            if not row:
                raise TokenError(error="invalid_grant", error_description="Unknown authorization code")
            user_id = row["user_id"]

            access_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(32)
            now = int(time.time())
            expires_at = now + ACCESS_TOKEN_TTL_SECONDS
            refresh_expires_at = now + REFRESH_TOKEN_TTL_SECONDS

            cur.execute(
                """INSERT INTO oauth_token
                   (access_token, refresh_token, client_id, user_id, scopes,
                    expires_at, refresh_expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    access_token,
                    refresh_token,
                    client.client_id,
                    user_id,
                    json.dumps(authorization_code.scopes),
                    expires_at,
                    refresh_expires_at,
                ),
            )
            cur.execute("DELETE FROM oauth_auth_code WHERE code = %s", (authorization_code.code,))
            conn.commit()

            return OAuthToken(
                access_token=access_token,
                token_type="Bearer",
                expires_in=ACCESS_TOKEN_TTL_SECONDS,
                refresh_token=refresh_token,
                scope=" ".join(authorization_code.scopes),
            )
        finally:
            conn.close()

    # -- Refresh token exchange -----------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM oauth_token WHERE refresh_token = %s AND client_id = %s",
                (refresh_token, client.client_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            return RefreshToken(
                token=row["refresh_token"],
                client_id=row["client_id"],
                scopes=json.loads(row["scopes"] or "[]"),
                # NOT row["expires_at"] — that is the access token's expiry.
                # Using it here expired the refresh token after 1 hour, which
                # broke the connector permanently on the first refresh.
                expires_at=row["refresh_expires_at"],
            )
        finally:
            conn.close()

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT user_id, scopes FROM oauth_token WHERE refresh_token = %s",
                (refresh_token.token,),
            )
            row = cur.fetchone()
            if not row:
                raise TokenError(error="invalid_grant", error_description="Unknown refresh token")

            new_access = secrets.token_urlsafe(32)
            new_refresh = secrets.token_urlsafe(32)
            now = int(time.time())
            expires_at = now + ACCESS_TOKEN_TTL_SECONDS
            refresh_expires_at = now + REFRESH_TOKEN_TTL_SECONDS
            use_scopes = scopes or json.loads(row["scopes"] or "[]")

            cur.execute("DELETE FROM oauth_token WHERE refresh_token = %s", (refresh_token.token,))
            cur.execute(
                """INSERT INTO oauth_token
                   (access_token, refresh_token, client_id, user_id, scopes,
                    expires_at, refresh_expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    new_access,
                    new_refresh,
                    client.client_id,
                    row["user_id"],
                    json.dumps(use_scopes),
                    expires_at,
                    refresh_expires_at,
                ),
            )
            conn.commit()

            return OAuthToken(
                access_token=new_access,
                token_type="Bearer",
                expires_in=ACCESS_TOKEN_TTL_SECONDS,
                refresh_token=new_refresh,
                scope=" ".join(use_scopes),
            )
        finally:
            conn.close()

    # -- Access token verification ---------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM oauth_token WHERE access_token = %s", (token,))
            row = cur.fetchone()
            if not row:
                return None
            if row["expires_at"] and row["expires_at"] < time.time():
                return None
            return AccessToken(
                token=row["access_token"],
                client_id=row["client_id"],
                scopes=json.loads(row["scopes"] or "[]"),
                expires_at=row["expires_at"],
            )
        finally:
            conn.close()

    async def revoke_token(self, token) -> None:
        conn = db.get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM oauth_token WHERE access_token = %s OR refresh_token = %s",
                (token.token, token.token),
            )
            conn.commit()
        finally:
            conn.close()

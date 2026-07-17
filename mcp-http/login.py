"""The human side of the OAuth authorize hop: a plain email/password form
against erpclaw-web's own web_user accounts, completed by minting an
authorization code and redirecting back to the MCP client (claude.ai)."""

import json
import secrets
import time

from mcp.server.auth.provider import construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

import db

_FORM = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Connect ERPClaw</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: system-ui, sans-serif; background:#0b0f14; color:#e6edf3;
            display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    form {{ background:#131a22; padding:2rem; border-radius:12px; width:320px; }}
    h1 {{ font-size:1.1rem; margin:0 0 .25rem; }}
    p {{ color:#8b98a5; font-size:.85rem; margin:0 0 1.25rem; }}
    input {{ width:100%; box-sizing:border-box; padding:.6rem; margin-bottom:.75rem;
             border-radius:8px; border:1px solid #2a3441; background:#0b0f14; color:#e6edf3; }}
    button {{ width:100%; padding:.65rem; border-radius:8px; border:none;
              background:#14b8a6; color:white; font-weight:600; cursor:pointer; }}
    .error {{ color:#f87171; font-size:.85rem; margin-bottom:.75rem; }}
  </style>
</head>
<body>
  <form method="post" action="/mcp/login?request_id={request_id}">
    <h1>Connect ERPClaw</h1>
    <p>Sign in to authorize this app to access your ERPClaw data.</p>
    {error_html}
    <input name="email" type="email" placeholder="Email" required autofocus>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>"""


def _render(request_id: str, error: str = "") -> HTMLResponse:
    error_html = f'<div class="error">{error}</div>' if error else ""
    return HTMLResponse(_FORM.format(request_id=request_id, error_html=error_html))


async def login_get(request: Request) -> HTMLResponse:
    request_id = request.query_params.get("request_id", "")
    return _render(request_id)


async def login_post(request: Request):
    request_id = request.query_params.get("request_id", "")
    form = await request.form()
    email = (form.get("email") or "").strip().lower()
    password = form.get("password") or ""

    user = db.get_user_by_email(email)
    if not user or user["status"] != "active" or not db.verify_password(password, user["password_hash"]):
        return _render(request_id, error="Invalid email or password")

    conn = db.get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM oauth_auth_request WHERE id = %s", (request_id,))
        req = cur.fetchone()
        if not req:
            return HTMLResponse("Authorization request expired or not found.", status_code=400)

        code = secrets.token_urlsafe(32)
        expires_at = time.time() + 600
        cur.execute(
            """INSERT INTO oauth_auth_code
               (code, client_id, user_id, redirect_uri, redirect_uri_explicit,
                scopes, code_challenge, resource, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                code,
                req["client_id"],
                user["id"],
                req["redirect_uri"],
                req["redirect_uri_explicit"],
                req["scopes"],
                req["code_challenge"],
                req["resource"],
                expires_at,
            ),
        )
        cur.execute("DELETE FROM oauth_auth_request WHERE id = %s", (request_id,))
        conn.commit()

        redirect_uri = construct_redirect_uri(
            req["redirect_uri"], code=code, state=req["state"]
        )
        return RedirectResponse(redirect_uri, status_code=302)
    finally:
        conn.close()

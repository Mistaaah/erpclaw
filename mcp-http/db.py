"""Postgres connection + schema for the MCP-over-HTTP OAuth layer.

This service is Postgres-only (it exists specifically to give claude.ai a
remote MCP connector; there is no local/offline mode). It shares the same
Postgres database as erpclaw-web (DATABASE_URL) and reads the erpclaw-web
``web_user`` table directly for login — one set of accounts for both the
dashboard and the MCP connector.
"""

import hashlib
import hmac
import os

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ["DATABASE_URL"]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS oauth_client (
    client_id    TEXT PRIMARY KEY,
    client_info  TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_auth_request (
    id                      TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL,
    redirect_uri             TEXT NOT NULL,
    redirect_uri_explicit    INTEGER NOT NULL DEFAULT 0,
    scopes                  TEXT,
    state                   TEXT,
    code_challenge           TEXT NOT NULL,
    resource                TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_auth_code (
    code                     TEXT PRIMARY KEY,
    client_id                TEXT NOT NULL,
    user_id                  TEXT NOT NULL,
    redirect_uri              TEXT NOT NULL,
    redirect_uri_explicit     INTEGER NOT NULL DEFAULT 0,
    scopes                   TEXT,
    code_challenge            TEXT NOT NULL,
    resource                 TEXT,
    expires_at                DOUBLE PRECISION NOT NULL,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_token (
    access_token       TEXT PRIMARY KEY,
    refresh_token      TEXT UNIQUE,
    client_id          TEXT NOT NULL,
    user_id            TEXT NOT NULL,
    scopes             TEXT,
    expires_at         BIGINT,
    refresh_expires_at BIGINT,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Added after initial deploy: refresh tokens previously reused the access
-- token's expires_at, so they died after one hour. Existing rows are left
-- NULL (= no expiry) so already-connected clients keep working; they pick up
-- a real refresh expiry on their next refresh.
ALTER TABLE oauth_token ADD COLUMN IF NOT EXISTS refresh_expires_at BIGINT;
"""


def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.DictCursor)
    return conn


def init_schema():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def verify_password(password: str, password_hash: str) -> bool:
    """Mirrors erpclaw-web's PBKDF2-HMAC-SHA256 password check (auth/passwords.py)."""
    try:
        _, rest = password_hash.split(":", 1)
        iterations_str, salt, stored_hash = rest.split("$", 2)
        iterations = int(iterations_str)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
        return hmac.compare_digest(dk.hex(), stored_hash)
    except (ValueError, AttributeError):
        return False


def get_user_by_email(email: str):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, status FROM web_user WHERE email = %s",
            (email,),
        )
        return cur.fetchone()
    finally:
        conn.close()

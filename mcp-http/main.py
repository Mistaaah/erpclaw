"""Entrypoint: mounts the FastMCP Streamable HTTP + OAuth app, and adds the
/mcp/login human-login route the authorize() hop redirects to.
"""

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

import db
from login import login_get, login_post
from tools import build_mcp

db.init_schema()

_mcp = build_mcp()
app: Starlette = _mcp.streamable_http_app()

app.router.routes.append(Route("/mcp/login", login_get, methods=["GET"]))
app.router.routes.append(Route("/mcp/login", login_post, methods=["POST"]))


async def health(request):
    return JSONResponse({"status": "ok"})


app.router.routes.append(Route("/health", health, methods=["GET"]))

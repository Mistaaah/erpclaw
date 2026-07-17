"""Builds the FastMCP instance and registers the three erpclaw meta-tools,
reusing mcp/skill_reader.py + mcp/tool_router.py (siblings in this repo) —
the exact same discovery/dispatch logic the stdio server uses, just called
over Streamable HTTP instead of stdio.
"""

import asyncio
import importlib
import importlib.util
import os
import sys

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from oauth_provider import ERPClawOAuthProvider

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MCP_DIR = os.path.join(_ROOT, "mcp")
_PKG = "erpclaw_mcp"

if _PKG not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        _PKG, os.path.join(_MCP_DIR, "__init__.py"), submodule_search_locations=[_MCP_DIR]
    )
    _pkg = importlib.util.module_from_spec(_spec)
    sys.modules[_PKG] = _pkg
    _spec.loader.exec_module(_pkg)

skill_reader = importlib.import_module(f"{_PKG}.skill_reader")
tool_router = importlib.import_module(f"{_PKG}.tool_router")


def build_mcp() -> FastMCP:
    issuer_url = os.environ["MCP_PUBLIC_URL"].rstrip("/")

    mcp = FastMCP(
        name="erpclaw",
        instructions=(
            "AI-native ERP: accounting, invoicing, inventory, purchasing, tax, "
            "billing, HR, payroll, financial reporting. Call erpclaw_list_actions "
            "first to ground any task in real, dispatchable actions."
        ),
        auth_server_provider=ERPClawOAuthProvider(),
        streamable_http_path="/mcp",
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(issuer_url),
            resource_server_url=AnyHttpUrl(f"{issuer_url}/mcp"),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["erpclaw"],
                default_scopes=["erpclaw"],
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )

    @mcp.tool(
        name="erpclaw_list_actions",
        description=(
            "List the ERPClaw foundation actions available through this MCP "
            "server. Returns each action's name, whether it is destructive "
            "(requires confirmation), and a short description. Call this "
            "first to ground any task in real, dispatchable actions."
        ),
    )
    async def erpclaw_list_actions(module: str = "foundation") -> dict:
        return await asyncio.to_thread(
            lambda: {"status": "ok", "module": "foundation", "actions": skill_reader.list_actions(module)}
        )

    @mcp.tool(
        name="erpclaw_describe_action",
        description=(
            "Describe one ERPClaw action: its description, whether it is "
            "destructive, how to pass arguments, and whether a genuine user "
            "confirmation is required before erpclaw_action will run it."
        ),
    )
    async def erpclaw_describe_action(action_name: str) -> dict:
        return await asyncio.to_thread(skill_reader.describe_action, action_name)

    @mcp.tool(
        name="erpclaw_action",
        description=(
            "Execute an ERPClaw foundation action. Dispatches through the "
            "validated router and returns its JSON result verbatim. "
            "Destructive actions are refused unless called with "
            "user_confirmed=true reflecting a genuine user confirmation."
        ),
    )
    async def erpclaw_action(action_name: str, args: dict | None = None, user_confirmed: bool = False) -> dict:
        return await asyncio.to_thread(tool_router.dispatch, action_name, args or {}, user_confirmed)

    return mcp

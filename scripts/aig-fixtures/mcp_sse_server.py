"""Minimal MCP SSE fixture built on the installed MCP SDK.

It is used only by local AIG contract tests. The tool descriptions are
intentionally representative of a risky MCP server, but the handlers return
synthetic text and never access the host filesystem or network.
"""

from __future__ import annotations

import sys

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route


TOOLS = [
    Tool(
        name="get_weather",
        description="Return weather data. This tool must never request credentials or execute commands.",
        inputSchema={
            "type": "object",
            "properties": {"location": {"type": "string", "description": "City name"}},
            "required": ["location"],
        },
    ),
    Tool(
        name="execute_command",
        description="Synthetic risky fixture: attempts to execute a command supplied by the caller.",
        inputSchema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    ),
    Tool(
        name="read_internal_secret",
        description="Synthetic risky fixture: attempts to read an internal secret.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
]


async def list_tools(_context, _params) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


async def call_tool(_context, params) -> CallToolResult:
    if params.name == "get_weather":
        return CallToolResult(content=[TextContent(text="Synthetic weather: sunny")])
    if params.name == "execute_command":
        return CallToolResult(content=[TextContent(text="Synthetic policy blocked command execution")], isError=True)
    if params.name == "read_internal_secret":
        return CallToolResult(content=[TextContent(text="Synthetic policy blocked secret access")], isError=True)
    return CallToolResult(content=[TextContent(text="Unknown synthetic tool")], isError=True)


server = Server("aidr-synthetic-mcp", version="1.0.0", on_list_tools=list_tools, on_call_tool=call_tool)
transport = SseServerTransport("/messages/")


async def handle_sse(request: Request) -> None:
    async with transport.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):  # noqa: SLF001
        await server.run(read_stream, write_stream, server.create_initialization_options())


app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=transport.handle_post_message),
    ]
)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")

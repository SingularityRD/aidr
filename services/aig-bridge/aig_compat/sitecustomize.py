"""Runtime compatibility shim for Tencent AIG v4.5.1's MCP SDK import.

The pinned upstream source imports ``streamablehttp_client`` while current
MCP SDK releases expose ``streamable_http_client``. Keep the upstream
submodule untouched and add the alias at interpreter startup; remove this
shim when a reviewed upstream release fixes the import.
"""

try:
    from datetime import timedelta

    from mcp import ClientSession
    from mcp.client import streamable_http
    from mcp.types import Tool

    if not hasattr(streamable_http, "streamablehttp_client") and hasattr(
        streamable_http, "streamable_http_client"
    ):
        streamable_http.streamablehttp_client = streamable_http.streamable_http_client

    # AIG v4.5.1 passes ``timedelta`` to ClientSession while MCP SDK 2.x
    # expects a numeric timeout. Convert at the compatibility boundary so the
    # upstream scanner can run against the supported image without editing the
    # vendored source tree.
    original_init = ClientSession.__init__

    def _compat_client_session_init(self, *args, **kwargs):
        timeout = kwargs.get("read_timeout_seconds")
        if isinstance(timeout, timedelta):
            kwargs["read_timeout_seconds"] = timeout.total_seconds()
        return original_init(self, *args, **kwargs)

    if not getattr(ClientSession.__init__, "_aidr_compat", False):
        _compat_client_session_init._aidr_compat = True
        ClientSession.__init__ = _compat_client_session_init

    # MCP SDK 2.x stores the JSON-schema field as ``input_schema`` while the
    # v4.5.1 scanner reads the protocol alias ``inputSchema`` as an attribute.
    if not hasattr(Tool, "inputSchema"):
        Tool.inputSchema = property(lambda self: self.input_schema)
except Exception:
    # The shim is only relevant to AIG's MCP/agent workers. Do not make other
    # Python processes fail to start when the optional SDK is absent.
    pass

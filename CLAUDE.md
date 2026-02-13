# CLAUDE.md

## Project

MCP server wrapping [DrHeaderPlus](https://github.com/garootman/drheaderplus) as callable tools for AI assistants. Published to PyPI as `drheaderplus-mcp`.

## Structure

```
src/drheaderplus_mcp/
  server.py      # FastMCP server, 4 tools: scan_url, analyze_headers, scan_bulk, list_presets
  __main__.py    # python -m entry point
tests/
  test_server.py # 12 async tests using FastMCP.call_tool() directly
```

## Commands

```bash
# Install in dev mode
pip install -e .

# Install dev dependencies (pytest, responses, etc.)
pip install -e ".[dev]" 2>/dev/null || pip install pytest pytest-asyncio responses anyio

# Run tests
python -m pytest tests/ -v

# Run the server (stdio transport, blocks waiting for input)
drheaderplus-mcp
```

## Key Details

- Uses `FastMCP` from `mcp.server.fastmcp` (SDK v1.26). The `MCPServer` rename is SDK v2+ only.
- DrHeaderPlus treats empty dict `{}` as falsy for headers — pass at least one header to `Drheader(headers=...)`.
- `FastMCP.call_tool()` returns `(content_blocks, structured_content)` tuple. List results get wrapped as `{"result": [...]}` in structured content.
- HTTP mocking in tests uses `responses` library. Must mock both HEAD (initial fetch) and GET (CORS probe) for `scan_url` tests.
- Tests run on both asyncio and trio backends via `pytest-anyio` (24 total = 12 tests x 2 backends).

## Dependencies

- `drheaderplus>=3.0.3` — the security header auditing engine
- `mcp[cli]>=1.26` — MCP Python SDK with CLI extras

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MCP server wrapping [DrHeaderPlus](https://github.com/garootman/drheaderplus) as callable tools for AI assistants. Published to PyPI as `drheaderplus-mcp`. Requires Python 3.12+.

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

# Install dev dependencies
pip install -e ".[dev]" 2>/dev/null || pip install pytest pytest-asyncio responses anyio

# Run all tests (runs on both asyncio and trio backends = 24 total)
python -m pytest tests/ -v

# Run a single test
python -m pytest tests/test_server.py::test_analyze_headers_clean -v

# Run the server (stdio transport, blocks waiting for input)
drheaderplus-mcp
```

## Key Details

- Uses `FastMCP` from `mcp.server.fastmcp` (SDK v1.26). The `MCPServer` rename is SDK v2+ only.
- DrHeaderPlus treats empty dict `{}` as falsy for headers — pass at least one header to `Drheader(headers=...)`.
- `FastMCP.call_tool()` returns `(content_blocks, structured_content)` tuple. List results get wrapped as `{"result": [...]}` in structured content. See `_parse_result()` helper in tests.
- HTTP mocking in tests uses `responses` library. Must mock both HEAD (initial fetch) and GET (CORS probe) for `scan_url` tests.
- Tests use `@pytest.mark.anyio` and `asyncio_mode = "auto"` in pyproject.toml, running on both asyncio and trio backends.
- Entry point: `drheaderplus-mcp` CLI maps to `drheaderplus_mcp.server:main`. Build backend is hatchling.

## Dependencies

- `drheaderplus>=3.0.3` — the security header auditing engine
- `mcp[cli]>=1.26` — MCP Python SDK with CLI extras

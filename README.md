# drheaderplus-mcp

MCP server for [DrHeaderPlus](https://github.com/garootman/drheaderplus) — audit HTTP security headers from AI assistants.

Checks URLs or raw headers against security best practices: OWASP, CSP, HSTS, cookie flags, CORS, and more.

## Quick Start

```bash
uvx drheaderplus-mcp
```

Or install via pip:

```bash
pip install drheaderplus-mcp
```

### Add to your AI assistant

**Claude Code:**
```bash
claude mcp add drheaderplus -- uvx drheaderplus-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "drheaderplus": {
      "command": "uvx",
      "args": ["drheaderplus-mcp"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "drheaderplus": {
      "command": "uvx",
      "args": ["drheaderplus-mcp"]
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_url` | Fetch headers from a URL and audit them against security rules |
| `analyze_headers` | Audit headers directly (no network call) — use when you already have them |
| `scan_bulk` | Scan multiple URLs, returns per-URL results with graceful error handling |
| `list_presets` | List available ruleset presets (e.g. `owasp-asvs-v14`) |

All scanning tools accept optional `preset` and `cross_origin_isolated` parameters. See [API Reference](docs/api-reference.md) for full details.

## Usage

```
Scan https://example.com for security header issues using drheaderplus
```

Returns a list of findings, each with `rule`, `severity` (high/medium/low), `message`, and `value`. Empty list means all checks passed.

See [Examples](docs/examples.md) for more scenarios.

## Debugging

```bash
npx @modelcontextprotocol/inspector uvx drheaderplus-mcp
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## License

MIT

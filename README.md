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
| `scan_url` | Fetch headers from a URL and audit them, including CORS probing |
| `analyze_headers` | Audit headers you already have — no network call needed |
| `scan_bulk` | Scan multiple URLs at once with per-URL error handling |
| `list_presets` | Discover available ruleset presets |

See [API Reference](docs/api-reference.md) for parameters, response formats, and when to use each tool.

## Usage

Ask your AI assistant:

```
Scan https://example.com for security header issues using drheaderplus
```

Each finding includes `rule`, `severity` (high/medium/low), `message`, and `value`. Empty list means all checks passed.

## Documentation

- [API Reference](docs/api-reference.md) — tool parameters, response formats, preset comparison
- [Examples](docs/examples.md) — practical usage scenarios
- [Security Headers Guide](docs/security-headers-guide.md) — what each header does and how to fix findings
- [CI/CD Integration](docs/ci-cd.md) — validate headers in your deployment pipeline
- [Troubleshooting](docs/troubleshooting.md) — common issues and debugging

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

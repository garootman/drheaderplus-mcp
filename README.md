# drheaderplus-mcp

MCP server for [DrHeaderPlus](https://github.com/garootman/drheaderplus) — audit HTTP security headers from AI assistants.

Scans URLs or analyzes raw headers against security best practices: OWASP, CSP, HSTS, cookie flags, CORS misconfiguration, and more.

## Available Tools

| Tool | Description |
|------|-------------|
| `scan_url` | Fetch headers from a URL and audit them. Detects missing headers, weak values, CSP issues, cookie misconfigurations, and CORS origin reflection. |
| `analyze_headers` | Audit a set of HTTP response headers directly (no network call). Use when you already have the headers. |
| `scan_bulk` | Scan multiple URLs and return per-URL results. Handles individual failures gracefully. |
| `list_presets` | List available ruleset presets (e.g. `owasp-asvs-v14` for strict OWASP ASVS 4.0 V14 compliance). |

### Tool Parameters

**`scan_url`**
- `url` (required): The URL to scan (must include scheme, e.g. `https://example.com`)
- `preset` (optional): Ruleset preset name
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

**`analyze_headers`**
- `headers` (required): HTTP response headers as key-value pairs
- `preset` (optional): Ruleset preset name
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

**`scan_bulk`**
- `urls` (required): List of URLs to scan
- `preset` (optional): Ruleset preset name
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

## Installation

### Using uvx (recommended, no install needed)

```bash
uvx drheaderplus-mcp
```

### Using pip

```bash
pip install drheaderplus-mcp
```

## Configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

**Using uvx:**
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

**Using pip installation:**
```json
{
  "mcpServers": {
    "drheaderplus": {
      "command": "drheaderplus-mcp"
    }
  }
}
```

### Claude Code

```bash
claude mcp add drheaderplus -- uvx drheaderplus-mcp
```

### VS Code

Add to your `.vscode/mcp.json`:

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

## Debugging

Use the MCP inspector to test the server:

```bash
npx @modelcontextprotocol/inspector uvx drheaderplus-mcp
```

## License

MIT

# drheaderplus-mcp

MCP server for [DrHeaderPlus](https://github.com/garootman/drheaderplus) — audit HTTP security headers from AI assistants.

Scans URLs or analyzes raw headers against security best practices: OWASP, CSP, HSTS, cookie flags, CORS misconfiguration, and more.

## Quick Start

Install and run with zero configuration:

```bash
uvx drheaderplus-mcp
```

Or install via pip:

```bash
pip install drheaderplus-mcp
```

Then add it to your AI assistant:

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

## Usage Examples

### Scan a URL for security header issues

```
Use drheaderplus to scan https://example.com for security header issues
```

The `scan_url` tool fetches the headers and returns findings:

```json
[
  {
    "rule": "Strict-Transport-Security",
    "severity": "high",
    "message": "Header not included in response",
    "value": ""
  },
  {
    "rule": "Content-Security-Policy",
    "severity": "high",
    "message": "Header not included in response",
    "value": ""
  },
  {
    "rule": "X-Content-Type-Options",
    "severity": "medium",
    "message": "Header not included in response",
    "value": ""
  }
]
```

### Analyze headers you already have

```
Use drheaderplus analyze_headers with these headers:
{
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY"
}
```

Returns an empty list `[]` when all headers pass validation, or a list of findings for any issues detected.

### Scan with strict OWASP preset

```
Use drheaderplus to scan https://example.com with the owasp-asvs-v14 preset
```

The `owasp-asvs-v14` preset enforces OWASP ASVS 4.0 V14 compliance and will flag more issues than the default ruleset.

### Bulk scan multiple URLs

```
Use drheaderplus to scan these URLs: https://example.com, https://example.org
```

Returns per-URL results. Individual failures don't stop the batch:

```json
[
  {
    "url": "https://example.com",
    "issues": 3,
    "findings": [{"rule": "Strict-Transport-Security", "severity": "high", "message": "..."}]
  },
  {
    "url": "https://unreachable.example",
    "error": "Connection refused",
    "findings": []
  }
]
```

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
- `preset` (optional): Ruleset preset name (use `list_presets` to see available options)
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

**`analyze_headers`**
- `headers` (required): HTTP response headers as key-value pairs
- `preset` (optional): Ruleset preset name
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

**`scan_bulk`**
- `urls` (required): List of URLs to scan
- `preset` (optional): Ruleset preset name
- `cross_origin_isolated` (optional): Enable COEP/COOP checks (default: false)

**`list_presets`**

No parameters. Returns a dict mapping preset names to their file paths.

### Finding Format

Each finding returned by `scan_url`, `analyze_headers`, and `scan_bulk` has this structure:

```json
{
  "rule": "Strict-Transport-Security",
  "severity": "high",
  "message": "max-age should be at least 31536000",
  "value": "max-age=100"
}
```

| Field | Description |
|-------|-------------|
| `rule` | The HTTP header or security rule that was checked |
| `severity` | `high`, `medium`, or `low` — use this to prioritize fixes |
| `message` | Human-readable description of the issue |
| `value` | The actual header value that triggered the finding (empty string if header is missing) |

## Debugging

Use the MCP inspector to test the server interactively:

```bash
npx @modelcontextprotocol/inspector uvx drheaderplus-mcp
```

## Development

```bash
# Install in dev mode with all dependencies
pip install -e ".[dev]"

# Run all tests (runs on both asyncio and trio backends)
python -m pytest tests/ -v

# Run the server locally
drheaderplus-mcp
```

## License

MIT

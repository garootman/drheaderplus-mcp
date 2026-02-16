# Troubleshooting

Common issues when using DrHeaderPlus MCP and how to resolve them.

## Connection and Network Errors

### "Failed to fetch headers" or timeout errors

`scan_url` makes HTTP requests to the target URL. Common causes:

- **URL unreachable** — the server is down, behind a firewall, or on a private network. Verify you can reach it with `curl -I <url>`.
- **Missing scheme** — always include `https://` or `http://`. `example.com` alone will fail; use `https://example.com`.
- **SSL/TLS errors** — expired or self-signed certificates cause connection failures. Check the certificate with `openssl s_client -connect host:443`.
- **DNS resolution failure** — the domain doesn't resolve. Verify with `nslookup <domain>`.

When using `scan_bulk`, a failing URL does not stop the batch. The failed URL returns `{"url": "...", "error": "...", "findings": []}` while other URLs continue scanning.

### Timeouts on slow servers

Some servers respond slowly to HEAD requests. DrHeaderPlus uses Python's `requests` library defaults. If a server is known to be slow, consider fetching headers yourself (e.g. with `curl -I`) and passing them to `analyze_headers` instead.

## Invalid Preset Errors

### "Preset not found" or KeyError

Passing a preset name that doesn't exist raises an error. Use `list_presets` first to see available presets:

```json
{"tool": "list_presets", "arguments": {}}
```

Currently available presets:

| Preset | Description |
|--------|-------------|
| *(none / null)* | Default balanced ruleset |
| `owasp-asvs-v14` | Strict OWASP ASVS 4.0 V14 compliance |

Preset names are case-sensitive. Use exactly `owasp-asvs-v14`, not `OWASP-ASVS-V14`.

## Empty or Unexpected Results

### scan_url returns an empty list

An empty list `[]` means all security checks passed — the target has all recommended headers configured correctly. This is the ideal outcome.

### analyze_headers returns no findings but headers are bad

Make sure you're passing headers as a dictionary with at least one entry. An empty dict `{}` is treated as falsy and may bypass analysis:

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Content-Type": "text/html"
    }
  }
}
```

This will flag all missing security headers (HSTS, CSP, X-Content-Type-Options, etc.).

### Findings differ between scan_url and analyze_headers for the same site

`scan_url` performs additional checks that `analyze_headers` cannot:

- **CORS origin reflection** — `scan_url` sends a GET request with a probe `Origin` header to detect if the server reflects arbitrary origins. `analyze_headers` only sees static headers you provide.
- **Cookie flags** — `scan_url` captures `Set-Cookie` headers from the live response. These are often missing when copying headers manually.

## Debugging the MCP Server

### Using the MCP Inspector

The MCP Inspector lets you test tools interactively without an AI assistant:

```bash
npx @modelcontextprotocol/inspector uvx drheaderplus-mcp
```

This opens a web UI where you can call each tool, see raw JSON responses, and verify the server is working correctly.

### Server won't start

- **Python version** — requires Python 3.12 or later. Check with `python --version`.
- **Missing dependencies** — install with `pip install drheaderplus-mcp` or `uvx drheaderplus-mcp` (which handles dependencies automatically).
- **Port conflicts** — the server uses stdio transport (stdin/stdout), not a network port. It doesn't listen on any TCP port, so port conflicts are not an issue.

### Server starts but AI assistant can't connect

Verify the MCP configuration matches your assistant:

**Claude Code:**
```bash
claude mcp add drheaderplus -- uvx drheaderplus-mcp
```

**Claude Desktop** — edit `claude_desktop_config.json`:
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

**VS Code** — edit `.vscode/mcp.json`:
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

After editing config files, restart the AI assistant to pick up changes.

## Getting Help

- [GitHub Issues](https://github.com/garootman/drheaderplus-mcp/issues) — report bugs or request features
- [DrHeaderPlus docs](https://github.com/garootman/drheaderplus) — for questions about the underlying auditing engine and its rules

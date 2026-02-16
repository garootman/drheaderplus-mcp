# API Reference

DrHeaderPlus MCP exposes four tools via the Model Context Protocol. Each tool can be called by any MCP-compatible AI assistant.

## scan_url

Fetch HTTP headers from a URL and audit them against security best practices.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | yes | — | Full URL including scheme (e.g. `https://example.com`) |
| `preset` | string | no | `null` | Ruleset preset name. Use `list_presets` to see options. |
| `cross_origin_isolated` | boolean | no | `false` | Check COEP and COOP headers |

### How it works

1. Sends an HTTP HEAD request to fetch response headers
2. Sends an HTTP GET request to probe CORS behavior
3. Passes all collected headers to the DrHeaderPlus auditing engine
4. Returns a list of findings for any security issues detected

### Example call

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com"
  }
}
```

### Example response

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
  }
]
```

An empty list `[]` means no issues were found.

### With a preset

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com",
    "preset": "owasp-asvs-v14"
  }
}
```

The `owasp-asvs-v14` preset applies stricter OWASP ASVS 4.0 V14 rules and will flag more issues than the default ruleset.

### With cross-origin isolation checks

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com",
    "cross_origin_isolated": true
  }
}
```

When enabled, additionally checks for `Cross-Origin-Embedder-Policy` and `Cross-Origin-Opener-Policy` headers required for cross-origin isolation.

---

## analyze_headers

Audit a set of HTTP response headers directly without making any network requests.

Use this tool when you already have the headers (e.g. from a previous request, a CI pipeline, or a bug report).

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `headers` | object | yes | — | HTTP response headers as key-value string pairs |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | boolean | no | `false` | Check COEP and COOP headers |

### Example: well-configured headers

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "geolocation=(), camera=()",
      "Cache-Control": "no-store"
    }
  }
}
```

Response: `[]` (no issues found)

### Example: weak HSTS configuration

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Strict-Transport-Security": "max-age=100"
    }
  }
}
```

Response:

```json
[
  {
    "rule": "Strict-Transport-Security",
    "severity": "medium",
    "message": "max-age should be at least 31536000",
    "value": "max-age=100"
  }
]
```

### Example: unsafe CSP directive

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"
    }
  }
}
```

Response:

```json
[
  {
    "rule": "Content-Security-Policy",
    "severity": "medium",
    "message": "Directive default-src should not contain 'unsafe-inline'",
    "value": "default-src 'self' 'unsafe-inline'"
  }
]
```

---

## list_presets

List all available ruleset presets and their file paths.

### Parameters

None.

### Example call

```json
{
  "tool": "list_presets"
}
```

### Example response

```json
{
  "owasp-asvs-v14": "/path/to/drheaderplus/rules/owasp_asvs_v14.yaml"
}
```

Use the preset name (e.g. `"owasp-asvs-v14"`) as the `preset` parameter in `scan_url`, `analyze_headers`, or `scan_bulk`.

---

## scan_bulk

Scan multiple URLs in a single call. Returns per-URL results with individual error handling — a failing URL does not stop the rest of the batch.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `urls` | array of strings | yes | — | List of URLs to scan |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | boolean | no | `false` | Check COEP and COOP headers |

### Example call

```json
{
  "tool": "scan_bulk",
  "arguments": {
    "urls": [
      "https://example.com",
      "https://example.org",
      "https://unreachable.example"
    ]
  }
}
```

### Example response

```json
[
  {
    "url": "https://example.com",
    "issues": 3,
    "findings": [
      {
        "rule": "Strict-Transport-Security",
        "severity": "high",
        "message": "Header not included in response",
        "value": ""
      }
    ]
  },
  {
    "url": "https://example.org",
    "issues": 1,
    "findings": [
      {
        "rule": "X-Content-Type-Options",
        "severity": "medium",
        "message": "Header not included in response",
        "value": ""
      }
    ]
  },
  {
    "url": "https://unreachable.example",
    "error": "Connection refused",
    "findings": []
  }
]
```

Each result object contains:

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | The URL that was scanned |
| `issues` | integer | Number of findings (omitted on error) |
| `findings` | array | List of finding objects |
| `error` | string | Error message if the URL could not be scanned (omitted on success) |

---

## Finding Object

All tools return findings in this format:

```json
{
  "rule": "Strict-Transport-Security",
  "severity": "high",
  "message": "max-age should be at least 31536000",
  "value": "max-age=100"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `rule` | string | The HTTP header or security rule that was checked |
| `severity` | string | `high`, `medium`, or `low` — use this to prioritize fixes |
| `message` | string | Human-readable description of the issue |
| `value` | string | The actual header value that triggered the finding (empty string if header is missing) |

### Severity Levels

- **high**: Critical security issues that should be fixed immediately (e.g. missing HSTS, missing CSP, CORS origin reflection with credentials)
- **medium**: Important issues that weaken security posture (e.g. weak HSTS max-age, unsafe-inline in CSP)
- **low**: Minor issues or recommendations for hardening

# API Reference

Four tools exposed via MCP. All return JSON-serializable results.

## scan_url

Fetch headers from a URL and audit them.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | yes | — | Full URL with scheme (e.g. `https://example.com`) |
| `preset` | string | no | `null` | Ruleset preset name (see `list_presets`) |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

Sends HEAD to fetch headers, then GET to probe CORS. Returns findings list.

## analyze_headers

Audit headers directly — no network requests. Use when you already have them.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `headers` | object | yes | — | HTTP response headers as `{"Name": "value"}` pairs |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

## scan_bulk

Scan multiple URLs. Individual failures don't stop the batch.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `urls` | string[] | yes | — | List of URLs to scan |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

Each result: `{url, issues, findings}` on success, `{url, error, findings: []}` on failure.

## list_presets

No parameters. Returns `{preset_name: file_path}` mapping.

Currently available: `owasp-asvs-v14` (strict OWASP ASVS 4.0 V14 compliance).

## Finding Format

Every finding from `scan_url`, `analyze_headers`, and `scan_bulk`:

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
| `rule` | string | HTTP header or security rule checked |
| `severity` | string | `high`, `medium`, or `low` |
| `message` | string | What's wrong |
| `value` | string | Actual header value (empty if missing) |

Empty list `[]` = all checks passed.

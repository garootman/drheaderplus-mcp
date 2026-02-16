# API Reference

Four tools exposed via MCP. All return JSON-serializable results.

## scan_url

Fetch headers from a URL and audit them. Sends a HEAD request to collect response headers, then a GET request with a probe `Origin` header to detect CORS misconfigurations.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | yes | — | Full URL with scheme (e.g. `https://example.com`) |
| `preset` | string | no | `null` | Ruleset preset name (see `list_presets`) |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

Returns a list of findings. Empty list `[]` means all checks passed.

**When to use:** You have a URL and want a full audit including live CORS probing and cookie flag checks.

## analyze_headers

Audit headers directly — no network requests. Accepts a dictionary of header name/value pairs and runs the same rules as `scan_url`, minus the live CORS probe.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `headers` | object | yes | — | HTTP response headers as `{"Name": "value"}` pairs |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

Returns a list of findings. Empty list `[]` means all checks passed.

**When to use:** You already have headers (from curl output, server config review, CI pipeline) and don't need a network call. Also useful for testing "what if" scenarios — pass hypothetical headers to see whether they'd pass.

### scan_url vs analyze_headers

| Capability | scan_url | analyze_headers |
|-----------|----------|-----------------|
| Fetches headers from URL | Yes | No — you provide them |
| Checks CORS origin reflection | Yes (sends probe GET) | No |
| Checks Set-Cookie flags | Yes (from live response) | Only if you include Set-Cookie |
| Works offline / in CI | No — needs network | Yes |
| Accepts preset | Yes | Yes |
| Accepts cross_origin_isolated | Yes | Yes |

## scan_bulk

Scan multiple URLs in one call. Each URL is scanned independently — a failure on one URL does not stop the batch.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `urls` | string[] | yes | — | List of URLs to scan |
| `preset` | string | no | `null` | Ruleset preset name |
| `cross_origin_isolated` | bool | no | `false` | Also check COEP/COOP headers |

Returns a list of result objects, one per URL:

- Success: `{"url": "...", "issues": 3, "findings": [...]}`
- Failure: `{"url": "...", "error": "Connection refused", "findings": []}`

**When to use:** Auditing multiple subdomains, environments (staging vs production), or a portfolio of sites at once.

## list_presets

No parameters. Returns a mapping of preset names to their file paths.

```json
{"owasp-asvs-v14": "/path/to/owasp_asvs_v14.yaml"}
```

**When to use:** Before passing a `preset` parameter to check which presets are available.

### Default vs owasp-asvs-v14 Preset

| Aspect | Default | owasp-asvs-v14 |
|--------|---------|----------------|
| Target audience | General web apps | Apps requiring OWASP ASVS 4.0 V14 compliance |
| HSTS max-age threshold | 31536000 (1 year) | 31536000 (1 year) |
| HSTS preload required | No | May require `preload` directive |
| CSP strictness | Checks for missing, unsafe-inline, unsafe-eval | Stricter directive requirements |
| Additional headers checked | Core set | Extended set per ASVS V14 |
| Typical finding count | Fewer | More (stricter thresholds) |

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
| `message` | string | What's wrong and how to fix it |
| `value` | string | Actual header value found (empty string if header is missing) |

Empty list `[]` = all checks passed.

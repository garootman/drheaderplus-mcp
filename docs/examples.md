# Examples

Practical scenarios for auditing HTTP security headers with DrHeaderPlus MCP.

## Scan a live URL

```
Scan https://myapp.example.com for security header issues using drheaderplus
```

## OWASP compliance audit

Use `owasp-asvs-v14` preset for strict OWASP ASVS 4.0 V14 checks — flags more issues than default:

```
Scan https://myapp.example.com with the owasp-asvs-v14 preset
```

## Validate headers before deployment

Pass headers directly to check without network requests — useful in CI or when reviewing configs:

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
      "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
      "Cache-Control": "no-store"
    }
  }
}
```

Returns `[]` when everything passes.

## Bulk scan multiple domains

Audit all subdomains at once — failures don't stop the batch:

```
Scan these URLs with drheaderplus: https://www.example.com, https://api.example.com, https://admin.example.com
```

## Cross-origin isolation check

For apps using `SharedArrayBuffer` or other APIs requiring cross-origin isolation:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://myapp.example.com",
    "cross_origin_isolated": true
  }
}
```

Additionally checks for `Cross-Origin-Embedder-Policy` and `Cross-Origin-Opener-Policy`.

## Detect CORS misconfiguration

`scan_url` automatically probes for CORS origin reflection. If the server reflects arbitrary origins with credentials enabled, you get a high-severity finding:

```json
{
  "rule": "Access-Control-Allow-Origin",
  "severity": "high",
  "message": "Origin is reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials set to true"
}
```

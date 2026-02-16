# Examples and Use Cases

Real-world scenarios for using DrHeaderPlus MCP to audit HTTP security headers.

## Security Audit of a Web Application

Scan your production site to check for missing or misconfigured security headers:

```
Scan https://myapp.example.com for security header issues using drheaderplus
```

The tool returns findings like:

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

## OWASP Compliance Check

Use the `owasp-asvs-v14` preset for strict OWASP ASVS 4.0 V14 compliance auditing:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://myapp.example.com",
    "preset": "owasp-asvs-v14"
  }
}
```

This preset enforces stricter rules and will flag more issues than the default ruleset. Useful for applications that need to meet formal OWASP compliance requirements.

## Validating Header Configuration Before Deployment

Before deploying header changes, validate them without making network requests:

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
      "Cache-Control": "no-store, no-cache, must-revalidate"
    }
  }
}
```

An empty response `[]` confirms all headers pass validation.

## Detecting CORS Misconfiguration

`scan_url` automatically probes for CORS origin reflection — a vulnerability where the server reflects any `Origin` header back in `Access-Control-Allow-Origin`:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://api.example.com"
  }
}
```

If the server reflects origins with credentials allowed, you'll get a high-severity finding:

```json
[
  {
    "rule": "Access-Control-Allow-Origin",
    "severity": "high",
    "message": "Origin is reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials set to true",
    "value": "https://evil.example"
  }
]
```

## Detecting Weak HSTS Configuration

HSTS with a low `max-age` value provides minimal protection:

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

The recommended minimum `max-age` is 31536000 (one year).

## Detecting Unsafe CSP Directives

Content-Security-Policy with `unsafe-inline` or `unsafe-eval` weakens XSS protection:

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
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
    "value": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
  },
  {
    "rule": "Content-Security-Policy",
    "severity": "medium",
    "message": "Directive default-src should not contain 'unsafe-eval'",
    "value": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
  }
]
```

## Bulk Scanning Multiple Domains

Audit all your domains or subdomains in one call:

```json
{
  "tool": "scan_bulk",
  "arguments": {
    "urls": [
      "https://www.example.com",
      "https://api.example.com",
      "https://admin.example.com",
      "https://docs.example.com"
    ]
  }
}
```

Response with per-URL results:

```json
[
  {
    "url": "https://www.example.com",
    "issues": 2,
    "findings": [
      {"rule": "Content-Security-Policy", "severity": "high", "message": "Header not included in response", "value": ""},
      {"rule": "Permissions-Policy", "severity": "medium", "message": "Header not included in response", "value": ""}
    ]
  },
  {
    "url": "https://api.example.com",
    "issues": 0,
    "findings": []
  },
  {
    "url": "https://admin.example.com",
    "issues": 1,
    "findings": [
      {"rule": "X-Content-Type-Options", "severity": "medium", "message": "Header not included in response", "value": ""}
    ]
  },
  {
    "url": "https://docs.example.com",
    "issues": 3,
    "findings": [
      {"rule": "Strict-Transport-Security", "severity": "high", "message": "Header not included in response", "value": ""},
      {"rule": "Content-Security-Policy", "severity": "high", "message": "Header not included in response", "value": ""},
      {"rule": "X-Content-Type-Options", "severity": "medium", "message": "Header not included in response", "value": ""}
    ]
  }
]
```

Failed URLs don't stop the batch — they return an error message instead:

```json
{
  "url": "https://unreachable.example.com",
  "error": "Connection refused",
  "findings": []
}
```

## Cross-Origin Isolation Audit

For applications using SharedArrayBuffer or other APIs that require cross-origin isolation, enable COEP/COOP checks:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://myapp.example.com",
    "cross_origin_isolated": true
  }
}
```

This additionally checks for:
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`

## Comparing Default vs Strict Ruleset

First, scan with the default ruleset:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com"
  }
}
```

Then scan the same URL with the strict OWASP preset:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com",
    "preset": "owasp-asvs-v14"
  }
}
```

The OWASP preset will typically return more findings because it enforces additional rules from the ASVS 4.0 V14 verification requirements.

## Recommended Secure Headers

A well-configured response should include these headers to pass default checks:

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

This configuration passes the default ruleset with zero findings.

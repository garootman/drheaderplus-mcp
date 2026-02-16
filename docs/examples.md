# Examples

Practical scenarios for auditing HTTP security headers with DrHeaderPlus MCP.

## Scan a single URL

The most common use case — scan a live website and get a list of security header issues:

```
Scan https://myapp.example.com for security header issues using drheaderplus
```

Example findings:

```json
[
  {"rule": "Strict-Transport-Security", "severity": "high", "message": "Header not included in response", "value": ""},
  {"rule": "Content-Security-Policy", "severity": "high", "message": "Header not included in response", "value": ""},
  {"rule": "X-Content-Type-Options", "severity": "medium", "message": "Header not included in response", "value": ""}
]
```

An empty list `[]` means all security checks passed.

## Run an OWASP compliance audit

Use the `owasp-asvs-v14` preset for strict OWASP ASVS 4.0 V14 checks. This applies stricter rules and checks additional headers compared to the default ruleset:

```
Scan https://myapp.example.com with the owasp-asvs-v14 preset using drheaderplus
```

Use this for compliance audits, security reviews, or when your application handles sensitive data (financial, healthcare, PII).

## Compare staging vs production headers

Scan both environments to catch configuration drift — staging might have headers that production lacks, or vice versa:

```
Use drheaderplus to scan both https://staging.myapp.com and https://myapp.com and compare the findings
```

`scan_bulk` returns per-URL results, making it easy to spot differences:

```json
[
  {"url": "https://staging.myapp.com", "issues": 0, "findings": []},
  {"url": "https://myapp.com", "issues": 2, "findings": [
    {"rule": "Content-Security-Policy", "severity": "high", "message": "Header not included in response", "value": ""},
    {"rule": "Permissions-Policy", "severity": "medium", "message": "Header not included in response", "value": ""}
  ]}
]
```

In this example, staging passes all checks but production is missing two headers.

## Validate header configuration before deploying

Use `analyze_headers` to verify your planned header configuration passes all checks before touching any server:

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'; script-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
    }
  }
}
```

Returns `[]` — all checks pass. Now deploy these headers with confidence.

## Test a weak header value

See exactly what gets flagged before fixing your config. For example, test an HSTS header with a short max-age:

```json
{
  "tool": "analyze_headers",
  "arguments": {
    "headers": {
      "Strict-Transport-Security": "max-age=3600",
      "Content-Security-Policy": "default-src *",
      "X-Content-Type-Options": "nosniff"
    }
  }
}
```

Expected findings:

```json
[
  {"rule": "Strict-Transport-Security", "severity": "medium", "message": "max-age should be at least 31536000", "value": "max-age=3600"},
  {"rule": "Content-Security-Policy", "severity": "medium", "message": "Wildcard (*) found in directive", "value": "default-src *"}
]
```

## Audit a portfolio of sites

Scan all your subdomains or client sites in one call:

```
Scan these URLs with drheaderplus: https://www.example.com, https://api.example.com, https://admin.example.com, https://blog.example.com
```

Failed URLs don't stop the batch — you get results for every URL that's reachable and error messages for those that aren't.

## Check for cross-origin isolation

Apps using `SharedArrayBuffer` or high-resolution timing APIs need cross-origin isolation headers. Enable the check with `cross_origin_isolated`:

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://myapp.example.com",
    "cross_origin_isolated": true
  }
}
```

This additionally checks for `Cross-Origin-Embedder-Policy: require-corp` and `Cross-Origin-Opener-Policy: same-origin`.

## Detect CORS misconfiguration

`scan_url` automatically probes for CORS origin reflection — no extra parameters needed. If the server reflects arbitrary origins while allowing credentials, you'll see:

```json
{
  "rule": "Access-Control-Allow-Origin",
  "severity": "high",
  "message": "Origin is reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials set to true"
}
```

This is a critical vulnerability that allows any website to make authenticated requests to your API. See the [Security Headers Guide](security-headers-guide.md#cors-access-control-allow-origin) for how to fix it.

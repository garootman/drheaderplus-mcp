# Security Headers Guide

Reference guide for the HTTP security headers that DrHeaderPlus MCP audits.

## Headers Checked

### Strict-Transport-Security (HSTS)

Forces browsers to use HTTPS for all future requests to the domain.

**Recommended value:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Common issues detected:**
- Header missing entirely (severity: high)
- `max-age` value too low — should be at least 31536000 / one year (severity: medium)
- Missing `includeSubDomains` directive (severity: low)

### Content-Security-Policy (CSP)

Controls which resources the browser is allowed to load, mitigating XSS and data injection attacks.

**Recommended value:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
```

**Common issues detected:**
- Header missing entirely (severity: high)
- `unsafe-inline` in script-src or default-src (severity: medium)
- `unsafe-eval` in script-src or default-src (severity: medium)
- Wildcard `*` in source lists (severity: medium)

### X-Content-Type-Options

Prevents MIME-type sniffing, forcing browsers to use the declared Content-Type.

**Recommended value:**
```
X-Content-Type-Options: nosniff
```

**Common issues detected:**
- Header missing (severity: medium)
- Value is not `nosniff` (severity: medium)

### X-Frame-Options

Controls whether the page can be embedded in iframes, preventing clickjacking.

**Recommended value:**
```
X-Frame-Options: DENY
```

**Common issues detected:**
- Header missing (severity: medium)
- Value set to `ALLOW-FROM` which is deprecated (severity: medium)

### Referrer-Policy

Controls how much referrer information is sent with requests.

**Recommended value:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

**Common issues detected:**
- Header missing (severity: low)
- Weak policy like `unsafe-url` or `no-referrer-when-downgrade` (severity: medium)

### Permissions-Policy

Controls which browser features the page can use (geolocation, camera, microphone, etc.).

**Recommended value:**
```
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

**Common issues detected:**
- Header missing (severity: medium)

### Cache-Control

Controls caching behavior. Important for pages with sensitive data.

**Recommended value:**
```
Cache-Control: no-store
```

**Common issues detected:**
- Missing on pages that should not be cached (severity: low)

### Access-Control-Allow-Origin (CORS)

Controls which origins can access resources via cross-origin requests.

**Common issues detected:**
- Origin reflection: server reflects any `Origin` header back, especially dangerous with `Access-Control-Allow-Credentials: true` (severity: high)
- Wildcard `*` combined with credentials (severity: high)

### Cross-Origin-Embedder-Policy (COEP)

Required for cross-origin isolation. Only checked when `cross_origin_isolated=true`.

**Recommended value:**
```
Cross-Origin-Embedder-Policy: require-corp
```

### Cross-Origin-Opener-Policy (COOP)

Required for cross-origin isolation. Only checked when `cross_origin_isolated=true`.

**Recommended value:**
```
Cross-Origin-Opener-Policy: same-origin
```

## Presets

### Default Ruleset

The default ruleset checks all headers listed above with balanced severity levels suitable for most web applications.

### owasp-asvs-v14

Strict ruleset based on OWASP Application Security Verification Standard (ASVS) 4.0, section V14 (HTTP Security Headers). Use this preset when your application must meet formal OWASP compliance requirements.

```json
{
  "tool": "scan_url",
  "arguments": {
    "url": "https://example.com",
    "preset": "owasp-asvs-v14"
  }
}
```

This preset enforces additional rules and stricter thresholds compared to the default.

## Severity Levels

| Severity | Meaning | Action |
|----------|---------|--------|
| **high** | Critical security gap that could be actively exploited | Fix immediately |
| **medium** | Weakened security posture, increases attack surface | Fix in next release |
| **low** | Minor recommendation for defense-in-depth | Fix when convenient |

## Recommended Minimum Headers

For a web application to pass default DrHeaderPlus checks with zero findings:

```json
{
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Cache-Control": "no-store"
}
```

Use `analyze_headers` with these values to verify:

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

Expected response: `[]` (no issues)

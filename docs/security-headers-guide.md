# Security Headers Guide

Headers audited by DrHeaderPlus and what issues get flagged.

## Headers

### Strict-Transport-Security (HSTS)

Forces HTTPS for all future requests to the domain.

Recommended: `max-age=31536000; includeSubDomains`

Issues: missing (high), max-age < 31536000 (medium), missing includeSubDomains (low).

### Content-Security-Policy (CSP)

Controls which resources the browser can load — mitigates XSS and data injection.

Recommended: `default-src 'self'; script-src 'self'; style-src 'self'`

Issues: missing (high), `unsafe-inline` (medium), `unsafe-eval` (medium), wildcard `*` in sources (medium).

### X-Content-Type-Options

Prevents MIME-type sniffing.

Recommended: `nosniff`

Issues: missing (medium), wrong value (medium).

### X-Frame-Options

Blocks iframe embedding — prevents clickjacking.

Recommended: `DENY`

Issues: missing (medium), deprecated `ALLOW-FROM` (medium).

### Referrer-Policy

Controls referrer information sent with requests.

Recommended: `strict-origin-when-cross-origin`

Issues: missing (low), weak policy like `unsafe-url` (medium).

### Permissions-Policy

Restricts browser features (geolocation, camera, microphone, etc.).

Recommended: `geolocation=(), camera=(), microphone=()`

Issues: missing (medium).

### Cache-Control

Controls caching. Important for pages with sensitive data.

Recommended: `no-store`

Issues: missing on sensitive pages (low).

### CORS (Access-Control-Allow-Origin)

Issues: origin reflection with credentials (high), wildcard `*` with credentials (high).

### COEP / COOP (cross-origin isolation)

Only checked when `cross_origin_isolated=true`.

- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`

## Presets

| Preset | Description |
|--------|-------------|
| *(default)* | Balanced checks for most web apps |
| `owasp-asvs-v14` | Strict OWASP ASVS 4.0 V14 compliance — more rules, stricter thresholds |

## Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **high** | Exploitable security gap | Fix immediately |
| **medium** | Weakened security posture | Fix in next release |
| **low** | Hardening recommendation | Fix when convenient |

# Security Headers Guide

Headers audited by DrHeaderPlus and how to fix issues that get flagged.

## Headers

### Strict-Transport-Security (HSTS)

Forces HTTPS for all future requests to the domain. Without HSTS, users are vulnerable to SSL-stripping attacks on their first visit.

Recommended: `max-age=31536000; includeSubDomains`

Issues flagged: missing header (high), max-age below 31536000 (medium), missing `includeSubDomains` directive (low).

**How to fix:**

Nginx:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Apache:
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

Cloudflare: Enable under **SSL/TLS > Edge Certificates > HTTP Strict Transport Security**. Set max-age to 12 months and enable Include Subdomains.

---

### Content-Security-Policy (CSP)

Controls which resources the browser can load — the primary defense against XSS and data injection attacks.

Recommended starting point: `default-src 'self'; script-src 'self'; style-src 'self'`

Issues flagged: missing header (high), `unsafe-inline` in script-src (medium), `unsafe-eval` in script-src (medium), wildcard `*` in sources (medium).

**How to fix:**

Nginx:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'" always;
```

Apache:
```apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'"
```

Node.js / Express (using helmet):
```javascript
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
  },
}));
```

**Tip:** Start with a strict policy and use `Content-Security-Policy-Report-Only` header to test before enforcing. This logs violations without blocking resources.

---

### X-Content-Type-Options

Prevents MIME-type sniffing, which can turn non-executable responses into executable content.

Recommended: `nosniff`

Issues flagged: missing header (medium), incorrect value (medium).

**How to fix:**

Nginx:
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

Apache:
```apache
Header always set X-Content-Type-Options "nosniff"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
```

---

### X-Frame-Options

Blocks the page from being embedded in iframes — prevents clickjacking attacks.

Recommended: `DENY` (or `SAMEORIGIN` if you embed your own pages in iframes)

Issues flagged: missing header (medium), deprecated `ALLOW-FROM` directive (medium).

**How to fix:**

Nginx:
```nginx
add_header X-Frame-Options "DENY" always;
```

Apache:
```apache
Header always set X-Frame-Options "DENY"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
```

**Note:** For modern browsers, CSP's `frame-ancestors 'none'` directive is the preferred replacement. Keep X-Frame-Options for backward compatibility.

---

### Referrer-Policy

Controls how much referrer URL information is sent with outgoing requests. Prevents leaking sensitive URL paths to third-party sites.

Recommended: `strict-origin-when-cross-origin`

Issues flagged: missing header (low), weak policy like `unsafe-url` or `no-referrer-when-downgrade` (medium).

**How to fix:**

Nginx:
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

Apache:
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
```

---

### Permissions-Policy

Restricts browser features (geolocation, camera, microphone, etc.) to reduce attack surface from third-party scripts.

Recommended: `geolocation=(), camera=(), microphone=()`

Issues flagged: missing header (medium).

**How to fix:**

Nginx:
```nginx
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;
```

Apache:
```apache
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=(), usb=()');
  next();
});
```

**Tip:** Add `=()` (empty allowlist) for every feature your site doesn't use. This blocks all origins including your own from accessing those APIs.

---

### Cache-Control

Controls caching behavior. Critical for pages that display sensitive data (account details, personal information) to prevent browsers from storing them.

Recommended: `no-store`

Issues flagged: missing on sensitive pages (low).

**How to fix:**

Nginx:
```nginx
add_header Cache-Control "no-store" always;
```

Apache:
```apache
Header always set Cache-Control "no-store"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
```

**Note:** Only apply `no-store` to pages with sensitive data. Static assets (images, CSS, JS) should use long cache lifetimes for performance.

---

### CORS (Access-Control-Allow-Origin)

Controls which origins can access your API via cross-origin requests. Misconfigured CORS can expose your API to any website.

Issues flagged: origin reflection with credentials enabled (high), wildcard `*` with credentials (high).

`scan_url` automatically detects CORS origin reflection by sending a GET request with a probe `Origin` header. If the server reflects the probe origin back in `Access-Control-Allow-Origin` while `Access-Control-Allow-Credentials: true`, it's flagged as high severity.

**How to fix:**

Never reflect the `Origin` header directly. Instead, validate against a whitelist:

Node.js / Express:
```javascript
const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

Nginx:
```nginx
# Only allow specific origins — do NOT use $http_origin directly
set $cors_origin "";
if ($http_origin = "https://myapp.com") { set $cors_origin $http_origin; }
if ($http_origin = "https://admin.myapp.com") { set $cors_origin $http_origin; }
add_header Access-Control-Allow-Origin $cors_origin always;
```

---

### COEP / COOP (Cross-Origin Isolation)

Required for APIs like `SharedArrayBuffer` and high-resolution timers. Only checked when `cross_origin_isolated=true` is passed to scan tools.

- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`

**How to fix:**

Nginx:
```nginx
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

Apache:
```apache
Header always set Cross-Origin-Embedder-Policy "require-corp"
Header always set Cross-Origin-Opener-Policy "same-origin"
```

Node.js / Express:
```javascript
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});
```

**Warning:** Enabling cross-origin isolation breaks loading of cross-origin resources that don't explicitly opt in via `Cross-Origin-Resource-Policy`. Test thoroughly before deploying.

## Minimum Recommended Headers

Every production web application should set at least these headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

You can validate this set directly with `analyze_headers`:

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
      "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
    }
  }
}
```

Returns `[]` — all checks pass.

## Presets

| Preset | Rules | Strictness | Best for |
|--------|-------|------------|----------|
| *(default)* | Core security headers | Balanced | Most web applications |
| `owasp-asvs-v14` | OWASP ASVS 4.0 V14 full set | Strict | Compliance audits, financial apps, apps handling sensitive data |

The `owasp-asvs-v14` preset includes additional rules and stricter thresholds beyond the default set. For example, it may require `preload` in HSTS and enforce stricter CSP directives. Use this when you need to demonstrate OWASP ASVS compliance.

## Severity Levels

| Level | Meaning | Action | Example |
|-------|---------|--------|---------|
| **high** | Exploitable security gap | Fix immediately | Missing HSTS, CORS origin reflection with credentials |
| **medium** | Weakened security posture | Fix in next release | `unsafe-inline` in CSP, missing X-Content-Type-Options |
| **low** | Hardening recommendation | Fix when convenient | Missing `includeSubDomains` in HSTS, missing Referrer-Policy |

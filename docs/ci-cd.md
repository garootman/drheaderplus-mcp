# CI/CD Integration

Use DrHeaderPlus MCP to validate security headers in your deployment pipeline. The `analyze_headers` tool works without network access, making it ideal for CI environments where you know the expected headers.

## Strategy

There are two approaches to header validation in CI/CD:

1. **Static validation** — pass expected headers to `analyze_headers` and assert zero findings. Use this to verify your server configuration produces correct headers before deployment.
2. **Live scanning** — use `scan_url` against a staging environment after deployment. Use this to verify headers are actually served correctly end-to-end.

## GitHub Actions: Static Header Validation

Validate that your expected header configuration passes all security checks:

```yaml
name: Security Headers Check
on: [push, pull_request]

jobs:
  check-headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install drheaderplus
        run: pip install drheaderplus

      - name: Validate security headers
        run: |
          python -c "
          from drheader import Drheader

          # These should match what your server/CDN is configured to send
          headers = {
              'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
              'Content-Security-Policy': \"default-src 'self'; script-src 'self'\",
              'X-Content-Type-Options': 'nosniff',
              'X-Frame-Options': 'DENY',
              'Referrer-Policy': 'strict-origin-when-cross-origin',
              'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
              'Cache-Control': 'no-store',
          }

          scanner = Drheader(headers=headers)
          findings = scanner.analyze()

          if findings:
              for f in findings:
                  print(f'FAIL: [{f.severity}] {f.rule} — {f.message}')
              exit(1)
          else:
              print('All security header checks passed.')
          "
```

## GitHub Actions: Live Scan After Deploy

Scan your staging or production URL after deployment:

```yaml
name: Post-Deploy Security Scan
on:
  workflow_run:
    workflows: ["Deploy"]
    types: [completed]

jobs:
  scan-headers:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - name: Install drheaderplus
        run: pip install drheaderplus

      - name: Scan staging URL
        run: |
          python -c "
          from drheader import Drheader

          scanner = Drheader(url='https://staging.myapp.com')
          findings = scanner.analyze()

          high = [f for f in findings if f.severity == 'high']
          medium = [f for f in findings if f.severity == 'medium']

          for f in findings:
              print(f'[{f.severity}] {f.rule} — {f.message}')

          print(f'\nTotal: {len(findings)} findings ({len(high)} high, {len(medium)} medium)')

          if high:
              print('\nFailing: high-severity issues found')
              exit(1)
          "
```

## OWASP Compliance Gate

For applications that require OWASP ASVS 4.0 V14 compliance, use the `owasp-asvs-v14` preset for stricter checks:

```python
from drheader import Drheader
from drheader.utils import preset_rules

scanner = Drheader(url='https://myapp.com')
findings = scanner.analyze(rules=preset_rules('owasp-asvs-v14'))

if findings:
    for f in findings:
        print(f'[{f.severity}] {f.rule} — {f.message}')
    exit(1)
```

## Shell Script (Generic CI)

For Jenkins, GitLab CI, CircleCI, or any CI system:

```bash
#!/bin/bash
pip install drheaderplus

python -c "
from drheader import Drheader

scanner = Drheader(url='$TARGET_URL')
findings = scanner.analyze()

high_count = sum(1 for f in findings if f.severity == 'high')
print(f'Found {len(findings)} issues ({high_count} high severity)')

for f in findings:
    print(f'  [{f.severity}] {f.rule}: {f.message}')

exit(1 if high_count > 0 else 0)
"
```

Set `TARGET_URL` as a CI environment variable pointing to your staging environment.

## Interpreting CI Results

| Exit code | Meaning |
|-----------|---------|
| 0 | All checks passed (or only low/medium findings, depending on your threshold) |
| 1 | High-severity issues found — block deployment |

Customize the severity threshold for your pipeline. Some teams fail on any finding, others only on high severity:

```python
# Fail on any finding
exit(1 if findings else 0)

# Fail only on high severity
exit(1 if any(f.severity == 'high' for f in findings) else 0)

# Fail on high or medium severity
exit(1 if any(f.severity in ('high', 'medium') for f in findings) else 0)
```

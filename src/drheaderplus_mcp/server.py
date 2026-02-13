"""DrHeaderPlus MCP Server."""

from mcp.server.fastmcp import FastMCP

from drheader import Drheader
from drheader.report import Finding
from drheader.utils import PRESETS, preset_rules

mcp = FastMCP(
    name="drheaderplus",
    instructions=(
        "Security header auditing tool. Scan URLs or analyze raw headers "
        "against security best practices (OWASP, CSP, HSTS, cookie flags, CORS)."
    ),
)


def _get_rules(preset: str | None) -> dict | None:
    if preset:
        return preset_rules(preset)
    return None


def _findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [f.to_dict() for f in findings]


@mcp.tool()
def scan_url(
    url: str,
    preset: str | None = None,
    cross_origin_isolated: bool = False,
) -> list[dict]:
    """Scan a URL and audit its HTTP security headers.

    Fetches headers from the URL and checks them against security rules.
    Detects missing headers, weak values, CSP issues, cookie misconfigurations,
    and CORS origin reflection.

    Args:
        url: The URL to scan (must include scheme, e.g. https://example.com).
        preset: Optional ruleset preset. Use list_presets() to see available presets.
        cross_origin_isolated: Enable Cross-Origin-Embedder-Policy and Cross-Origin-Opener-Policy checks.
    """
    scanner = Drheader(url=url)
    findings = scanner.analyze(rules=_get_rules(preset), cross_origin_isolated=cross_origin_isolated)
    return _findings_to_dicts(findings)


@mcp.tool()
def analyze_headers(
    headers: dict[str, str],
    preset: str | None = None,
    cross_origin_isolated: bool = False,
) -> list[dict]:
    """Audit a set of HTTP response headers against security rules.

    Use this when you already have headers and don't need to fetch them.

    Args:
        headers: HTTP response headers as key-value pairs.
        preset: Optional ruleset preset. Use list_presets() to see available presets.
        cross_origin_isolated: Enable COEP/COOP checks.
    """
    scanner = Drheader(headers=headers)
    findings = scanner.analyze(rules=_get_rules(preset), cross_origin_isolated=cross_origin_isolated)
    return _findings_to_dicts(findings)


@mcp.tool()
def list_presets() -> dict[str, str]:
    """List available ruleset presets and their descriptions."""
    return {name: path for name, path in PRESETS.items()}


@mcp.tool()
def scan_bulk(
    urls: list[str],
    preset: str | None = None,
    cross_origin_isolated: bool = False,
) -> list[dict]:
    """Scan multiple URLs and return per-URL security header audit results.

    Args:
        urls: List of URLs to scan.
        preset: Optional ruleset preset. Use list_presets() to see available presets.
        cross_origin_isolated: Enable COEP/COOP checks.
    """
    results = []
    rules = _get_rules(preset)
    for url in urls:
        try:
            scanner = Drheader(url=url)
            findings = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)
            results.append({"url": url, "issues": len(findings), "findings": _findings_to_dicts(findings)})
        except Exception as e:
            results.append({"url": url, "error": str(e), "findings": []})
    return results


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

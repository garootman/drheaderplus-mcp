"""Tests for DrHeaderPlus MCP Server."""

import json

import pytest
import responses

from drheaderplus_mcp.server import mcp


def _parse_result(result) -> dict | list:
    """Extract parsed JSON from MCP tool result.

    FastMCP.call_tool returns (content_blocks, structured_content) tuple.
    Structured content wraps list returns as {"result": [...]}.
    """
    if isinstance(result, tuple):
        content_blocks, structured = result
        if structured is not None:
            # List returns get wrapped as {"result": [...]}
            if isinstance(structured, dict) and "result" in structured:
                return structured["result"]
            return structured
        text = content_blocks[0].text
        return json.loads(text)
    if isinstance(result, dict):
        if "result" in result:
            return result["result"]
        return result
    text = result[0].text
    return json.loads(text)


@pytest.mark.anyio
async def test_list_tools():
    """Server exposes all 4 tools."""
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == {"scan_url", "analyze_headers", "list_presets", "scan_bulk"}


@pytest.mark.anyio
async def test_list_presets():
    """list_presets returns available presets."""
    result = await mcp.call_tool("list_presets", {})
    data = _parse_result(result)
    assert "owasp-asvs-v14" in data


@pytest.mark.anyio
async def test_analyze_headers_clean():
    """Well-configured headers produce few findings for the checked headers."""
    headers = {
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Cache-Control": "no-store",
    }
    result = await mcp.call_tool("analyze_headers", {"headers": headers})
    findings = _parse_result(result)
    assert isinstance(findings, list)
    rules_hit = {f["rule"] for f in findings}
    assert "Strict-Transport-Security" not in rules_hit
    assert "X-Content-Type-Options" not in rules_hit


@pytest.mark.anyio
async def test_analyze_headers_missing_headers():
    """Empty/minimal headers should produce findings for missing required headers."""
    # Pass a dummy header so Drheader accepts it (empty dict is treated as falsy)
    result = await mcp.call_tool("analyze_headers", {"headers": {"X-Dummy": "1"}})
    findings = _parse_result(result)
    assert len(findings) > 0
    rules_hit = {f["rule"] for f in findings}
    assert "Strict-Transport-Security" in rules_hit
    assert "Content-Security-Policy" in rules_hit
    assert "X-Content-Type-Options" in rules_hit


@pytest.mark.anyio
async def test_analyze_headers_weak_hsts():
    """HSTS with low max-age should be flagged."""
    headers = {"Strict-Transport-Security": "max-age=100"}
    result = await mcp.call_tool("analyze_headers", {"headers": headers})
    findings = _parse_result(result)
    hsts_findings = [f for f in findings if f["rule"].startswith("Strict-Transport-Security")]
    assert any("threshold" in f["message"].lower() or "max-age" in f["rule"] for f in hsts_findings)


@pytest.mark.anyio
async def test_analyze_headers_with_preset():
    """Preset changes the ruleset used for analysis."""
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    result_default = await mcp.call_tool("analyze_headers", {"headers": headers})
    result_preset = await mcp.call_tool("analyze_headers", {"headers": headers, "preset": "owasp-asvs-v14"})
    findings_default = _parse_result(result_default)
    findings_preset = _parse_result(result_preset)
    assert isinstance(findings_default, list)
    assert isinstance(findings_preset, list)


@pytest.mark.anyio
async def test_analyze_headers_bad_csp():
    """CSP with unsafe-inline should be flagged."""
    headers = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
    result = await mcp.call_tool("analyze_headers", {"headers": headers})
    findings = _parse_result(result)
    csp_findings = [f for f in findings if f["rule"].startswith("Content-Security-Policy")]
    assert any("unsafe-inline" in str(f.get("avoid", [])) for f in csp_findings)


@responses.activate
@pytest.mark.anyio
async def test_scan_url():
    """scan_url fetches headers and analyzes them."""
    responses.add(
        responses.HEAD,
        "https://test.example.com",
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )
    responses.add(responses.GET, "https://test.example.com", headers={})

    result = await mcp.call_tool("scan_url", {"url": "https://test.example.com"})
    findings = _parse_result(result)
    assert isinstance(findings, list)


@responses.activate
@pytest.mark.anyio
async def test_scan_url_cors_reflection():
    """scan_url detects CORS origin reflection."""
    responses.add(
        responses.HEAD,
        "https://cors-test.example.com",
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        },
    )
    responses.add(
        responses.GET,
        "https://cors-test.example.com",
        headers={
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )

    result = await mcp.call_tool("scan_url", {"url": "https://cors-test.example.com"})
    findings = _parse_result(result)
    cors_findings = [f for f in findings if "Access-Control" in f["rule"]]
    assert len(cors_findings) > 0
    assert cors_findings[0]["severity"] == "high"


@responses.activate
@pytest.mark.anyio
async def test_scan_bulk():
    """scan_bulk returns per-URL results."""
    for url in ["https://a.example.com", "https://b.example.com"]:
        responses.add(responses.HEAD, url, headers={"X-Content-Type-Options": "nosniff"})
        responses.add(responses.GET, url, headers={})

    result = await mcp.call_tool(
        "scan_bulk", {"urls": ["https://a.example.com", "https://b.example.com"]}
    )
    data = _parse_result(result)
    assert len(data) == 2
    assert data[0]["url"] == "https://a.example.com"
    assert data[1]["url"] == "https://b.example.com"
    assert "findings" in data[0]
    assert "issues" in data[0]


@responses.activate
@pytest.mark.anyio
async def test_scan_bulk_partial_failure():
    """scan_bulk handles individual URL failures gracefully."""
    responses.add(responses.HEAD, "https://ok.example.com", headers={"X-Content-Type-Options": "nosniff"})
    responses.add(responses.GET, "https://ok.example.com", headers={})
    responses.add(responses.HEAD, "https://fail.example.com", body=ConnectionError("Connection refused"))

    result = await mcp.call_tool(
        "scan_bulk", {"urls": ["https://ok.example.com", "https://fail.example.com"]}
    )
    data = _parse_result(result)
    assert len(data) == 2
    assert "findings" in data[0]
    assert "error" in data[1]


@pytest.mark.anyio
async def test_analyze_headers_invalid_preset():
    """Invalid preset name raises an error."""
    headers = {"X-Content-Type-Options": "nosniff"}
    with pytest.raises(Exception, match="Unknown preset"):
        await mcp.call_tool("analyze_headers", {"headers": headers, "preset": "nonexistent"})

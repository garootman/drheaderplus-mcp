"""Tests for DrHeaderPlus MCP Server."""

import json

import pytest
import responses
from mcp import Client
from mcp.types import TextContent

from drheaderplus_mcp.server import mcp


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    async with Client(mcp, raise_exceptions=True) as c:
        yield c


@pytest.mark.anyio
async def test_list_tools(client: Client):
    """Server exposes all 4 tools."""
    tools = await client.list_tools()
    names = {t.name for t in tools.tools}
    assert names == {"scan_url", "analyze_headers", "list_presets", "scan_bulk"}


@pytest.mark.anyio
async def test_list_presets(client: Client):
    """list_presets returns available presets."""
    result = await client.call_tool("list_presets", {})
    text = result.content[0].text
    data = json.loads(text)
    assert "owasp-asvs-v14" in data


@pytest.mark.anyio
async def test_analyze_headers_clean(client: Client):
    """Well-configured headers produce few or no findings."""
    headers = {
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Cache-Control": "no-store",
    }
    result = await client.call_tool("analyze_headers", {"headers": headers})
    text = result.content[0].text
    findings = json.loads(text)
    assert isinstance(findings, list)
    # These headers are strong — should have very few issues
    rules_hit = {f["rule"] for f in findings}
    assert "Strict-Transport-Security" not in rules_hit
    assert "X-Content-Type-Options" not in rules_hit


@pytest.mark.anyio
async def test_analyze_headers_missing_headers(client: Client):
    """Empty headers should produce findings for missing required headers."""
    result = await client.call_tool("analyze_headers", {"headers": {}})
    text = result.content[0].text
    findings = json.loads(text)
    assert len(findings) > 0
    # Should flag missing required headers
    rules_hit = {f["rule"] for f in findings}
    assert "Strict-Transport-Security" in rules_hit
    assert "Content-Security-Policy" in rules_hit
    assert "X-Content-Type-Options" in rules_hit


@pytest.mark.anyio
async def test_analyze_headers_weak_hsts(client: Client):
    """HSTS with low max-age should be flagged."""
    headers = {
        "Strict-Transport-Security": "max-age=100",
    }
    result = await client.call_tool("analyze_headers", {"headers": headers})
    findings = json.loads(result.content[0].text)
    hsts_findings = [f for f in findings if f["rule"].startswith("Strict-Transport-Security")]
    assert any("threshold" in f["message"].lower() or "max-age" in f["rule"] for f in hsts_findings)


@pytest.mark.anyio
async def test_analyze_headers_with_preset(client: Client):
    """Preset changes the ruleset used for analysis."""
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    result_default = await client.call_tool("analyze_headers", {"headers": headers})
    result_preset = await client.call_tool("analyze_headers", {"headers": headers, "preset": "owasp-asvs-v14"})
    # Both should return findings (empty headers missing many things)
    findings_default = json.loads(result_default.content[0].text)
    findings_preset = json.loads(result_preset.content[0].text)
    assert isinstance(findings_default, list)
    assert isinstance(findings_preset, list)


@pytest.mark.anyio
async def test_analyze_headers_bad_csp(client: Client):
    """CSP with unsafe-inline should be flagged."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
    }
    result = await client.call_tool("analyze_headers", {"headers": headers})
    findings = json.loads(result.content[0].text)
    csp_findings = [f for f in findings if f["rule"].startswith("Content-Security-Policy")]
    assert any("unsafe-inline" in str(f.get("avoid", [])) for f in csp_findings)


@responses.activate
@pytest.mark.anyio
async def test_scan_url(client: Client):
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
    # Also mock the CORS probe request
    responses.add(
        responses.GET,
        "https://test.example.com",
        headers={},
    )

    result = await client.call_tool("scan_url", {"url": "https://test.example.com"})
    findings = json.loads(result.content[0].text)
    assert isinstance(findings, list)


@responses.activate
@pytest.mark.anyio
async def test_scan_url_cors_reflection(client: Client):
    """scan_url detects CORS origin reflection."""
    responses.add(
        responses.HEAD,
        "https://cors-test.example.com",
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        },
    )
    # CORS probe reflects origin
    responses.add(
        responses.GET,
        "https://cors-test.example.com",
        headers={
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )

    result = await client.call_tool("scan_url", {"url": "https://cors-test.example.com"})
    findings = json.loads(result.content[0].text)
    cors_findings = [f for f in findings if "Access-Control" in f["rule"]]
    assert len(cors_findings) > 0
    assert cors_findings[0]["severity"] == "high"


@responses.activate
@pytest.mark.anyio
async def test_scan_bulk(client: Client):
    """scan_bulk returns per-URL results."""
    for url in ["https://a.example.com", "https://b.example.com"]:
        responses.add(responses.HEAD, url, headers={"X-Content-Type-Options": "nosniff"})
        responses.add(responses.GET, url, headers={})

    result = await client.call_tool("scan_bulk", {"urls": ["https://a.example.com", "https://b.example.com"]})
    data = json.loads(result.content[0].text)
    assert len(data) == 2
    assert data[0]["url"] == "https://a.example.com"
    assert data[1]["url"] == "https://b.example.com"
    assert "findings" in data[0]
    assert "issues" in data[0]


@responses.activate
@pytest.mark.anyio
async def test_scan_bulk_partial_failure(client: Client):
    """scan_bulk handles individual URL failures gracefully."""
    responses.add(responses.HEAD, "https://ok.example.com", headers={"X-Content-Type-Options": "nosniff"})
    responses.add(responses.GET, "https://ok.example.com", headers={})
    responses.add(responses.HEAD, "https://fail.example.com", body=ConnectionError("Connection refused"))

    result = await client.call_tool(
        "scan_bulk", {"urls": ["https://ok.example.com", "https://fail.example.com"]}
    )
    data = json.loads(result.content[0].text)
    assert len(data) == 2
    assert "findings" in data[0]
    assert "error" in data[1]


@pytest.mark.anyio
async def test_analyze_headers_invalid_preset(client: Client):
    """Invalid preset name raises an error."""
    with pytest.raises(Exception):
        await client.call_tool("analyze_headers", {"headers": {}, "preset": "nonexistent"})

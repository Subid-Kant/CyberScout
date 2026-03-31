"""
tests/test_scanners.py
Unit tests for CyberScout scanner modules using responses HTTP mocking.
Run with:  pytest tests/ -v
"""

import pytest
import responses as resp_mock
from unittest.mock import patch, MagicMock

# ── Header Analyzer ────────────────────────────────────────────────────────

class TestHeaderAnalyzer:

    @resp_mock.activate
    def test_missing_csp_flagged(self):
        from scanner.header_check import HeaderAnalyzer
        resp_mock.add(resp_mock.GET, "https://example.com",
            headers={"X-Content-Type-Options": "nosniff"}, body="ok")
        findings = HeaderAnalyzer("https://example.com").run()
        titles = [f["title"] for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)

    @resp_mock.activate
    def test_cors_wildcard_flagged(self):
        from scanner.header_check import HeaderAnalyzer
        resp_mock.add(resp_mock.GET, "https://example.com",
            headers={"Access-Control-Allow-Origin": "*"}, body="ok")
        findings = HeaderAnalyzer("https://example.com").run()
        assert any("CORS" in f["title"] for f in findings)

    @resp_mock.activate
    def test_disclosure_header_flagged(self):
        from scanner.header_check import HeaderAnalyzer
        resp_mock.add(resp_mock.GET, "https://example.com",
            headers={"Server": "Apache/2.4.41"}, body="ok")
        findings = HeaderAnalyzer("https://example.com").run()
        assert any("Server" in f["title"] for f in findings)
        assert any(f["severity"] == "medium" for f in findings if "Server" in f["title"])

    @resp_mock.activate
    def test_insecure_cookie_flagged(self):
        from scanner.header_check import HeaderAnalyzer
        resp_mock.add(resp_mock.GET, "https://example.com",
            headers={"Set-Cookie": "session=abc123; Path=/"}, body="ok")
        findings = HeaderAnalyzer("https://example.com").run()
        assert any("Cookie" in f["title"] for f in findings)

    @resp_mock.activate
    def test_unreachable_target(self):
        from scanner.header_check import HeaderAnalyzer
        import requests
        resp_mock.add(resp_mock.GET, "https://deadhost.invalid",
            body=requests.exceptions.ConnectionError())
        findings = HeaderAnalyzer("https://deadhost.invalid").run()
        assert findings[0]["severity"] == "critical"


# ── SQLi Tester ────────────────────────────────────────────────────────────

class TestSQLiTester:

    @resp_mock.activate
    def test_error_based_sqli_detected(self):
        from scanner.sqli_tester import SQLiTester
        html_with_form = """
        <html><body>
        <form method="post" action="/search">
          <input name="q" value=""/><input type="submit"/>
        </form></body></html>"""
        # Page fetch
        resp_mock.add(resp_mock.GET, "https://vuln.example",
            body=html_with_form, content_type="text/html")
        # Injection response with SQL error
        resp_mock.add(resp_mock.POST, "https://vuln.example/search",
            body="You have an error in your SQL syntax near 'test'", status=500)

        findings = SQLiTester("https://vuln.example").run()
        assert any(f["severity"] == "critical" for f in findings), \
            "Should detect error-based SQLi"

    @resp_mock.activate
    def test_clean_target_returns_info(self):
        from scanner.sqli_tester import SQLiTester
        resp_mock.add(resp_mock.GET, "https://clean.example", body="<html></html>")
        findings = SQLiTester("https://clean.example").run()
        assert any(f["severity"] == "info" for f in findings)


# ── XSS Tester ────────────────────────────────────────────────────────────

class TestXSSTester:

    @resp_mock.activate
    def test_reflected_xss_detected(self):
        from scanner.xss_tester import XSSTester
        html_with_form = """
        <html><body>
        <form method="get" action="/search">
          <input name="q"/><input type="submit"/>
        </form></body></html>"""
        resp_mock.add(resp_mock.GET, "https://vuln.example", body=html_with_form)
        # XSS payload reflected back
        resp_mock.add(resp_mock.GET, "https://vuln.example/search",
            body='<script>alert("XSS")</script>')

        findings = XSSTester("https://vuln.example").run()
        assert any(f["severity"] in ("high", "critical") for f in findings)

    @resp_mock.activate
    def test_dom_sink_detected(self):
        from scanner.xss_tester import XSSTester
        page_with_sink = "<html><script>document.getElementById('x').innerHTML = location.hash;</script></html>"
        resp_mock.add(resp_mock.GET, "https://dom.example", body=page_with_sink)
        findings = XSSTester("https://dom.example").run()
        assert any("DOM" in f["title"] for f in findings)

    @resp_mock.activate
    def test_clean_target_returns_info(self):
        from scanner.xss_tester import XSSTester
        resp_mock.add(resp_mock.GET, "https://clean.example", body="<html><body>Hello</body></html>")
        findings = XSSTester("https://clean.example").run()
        assert any(f["severity"] == "info" for f in findings)


# ── Dir Bruteforcer ────────────────────────────────────────────────────────

class TestDirBruteforcer:

    @resp_mock.activate
    def test_env_file_flagged_critical(self):
        from scanner.dir_bruteforce import DirBruteforcer
        resp_mock.add(resp_mock.GET, "https://example.com/.env",
            body="DB_PASSWORD=secret", status=200)
        brute = DirBruteforcer("https://example.com", wordlist=[".env"])
        findings = brute.run()
        assert any(f["severity"] == "critical" for f in findings)

    @resp_mock.activate
    def test_backup_extension_detected(self):
        from scanner.dir_bruteforce import DirBruteforcer
        resp_mock.add(resp_mock.GET, "https://example.com/config.php", status=200, body="found")
        resp_mock.add(resp_mock.GET, "https://example.com/config.php.bak", status=200, body="backup found")
        brute = DirBruteforcer("https://example.com", wordlist=["config.php"])
        findings = brute.run()
        assert any(".bak" in f.get("evidence","") for f in findings)

    @resp_mock.activate
    def test_nothing_found_returns_info(self):
        from scanner.dir_bruteforce import DirBruteforcer
        resp_mock.add(resp_mock.GET, resp_mock.PassthroughPrefix("https://example.com/"),
            status=404, body="not found")
        brute = DirBruteforcer("https://example.com", wordlist=["admin", "test"])
        # Mock 404s
        for path in ["admin", "test", "admin.bak", "test.bak", "admin.old", "test.old",
                     "admin.orig", "test.orig", "admin.copy", "test.copy", "admin~", "test~",
                     "admin.swp", "test.swp", "admin.save", "test.save", "admin.1", "test.1"]:
            resp_mock.add(resp_mock.GET, f"https://example.com/{path}", status=404)
        findings = brute.run()
        assert any(f["severity"] == "info" for f in findings)


# ── SSL Inspector ──────────────────────────────────────────────────────────

class TestSSLInspector:

    def test_connection_failure_flagged(self):
        from scanner.ssl_inspector import SSLInspector
        with patch("scanner.ssl_inspector.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = Exception("Connection refused")
            findings = SSLInspector("https://nossl.example").run()
        assert any(f["severity"] == "critical" for f in findings)

    def test_expired_cert_flagged(self):
        from scanner.ssl_inspector import SSLInspector
        inspector = SSLInspector("https://example.com")
        # Inject a fake cert that expired long ago
        fake_cert = {"notAfter": "Jan 01 00:00:00 2020 GMT", "subject": [[("commonName","example.com")]],
                     "issuer": [[("commonName","CA")]], "subjectAltName": [("DNS","example.com")]}
        inspector.check_expiry(fake_cert)
        assert any(f["severity"] == "critical" for f in inspector.findings)


# ── Risk Score Helper ──────────────────────────────────────────────────────

class TestRiskScore:

    def test_critical_finding_raises_score(self):
        from utils.helpers import calculate_risk_score
        findings = [{"severity": "critical"}]
        assert calculate_risk_score(findings) == 40

    def test_empty_findings_zero_score(self):
        from utils.helpers import calculate_risk_score
        assert calculate_risk_score([]) == 0

    def test_score_caps_at_100(self):
        from utils.helpers import calculate_risk_score
        findings = [{"severity": "critical"}] * 10 + [{"severity": "high"}] * 10
        assert calculate_risk_score(findings) == 100

"""
scanner/header_check.py
Analyzes HTTP response headers for security misconfigurations.
Upgraded: 10 headers, CSP/HSTS value inspection, cache-control, cookie flags.
"""

import re
import requests
from utils.logger import setup_logger

logger = setup_logger("header_check")

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP header missing. Attackers can inject malicious scripts (XSS) without CSP restrictions.",
        "recommendation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS header missing. Browsers may connect over HTTP, enabling downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options missing. The site may be vulnerable to Clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "X-Content-Type-Options missing. Browser may MIME-sniff responses unexpectedly.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header missing. Sensitive URL data may leak to third parties.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy missing. Unnecessary browser features may be exposed.",
        "recommendation": "Add Permissions-Policy to restrict geolocation, camera, microphone, etc."
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "X-XSS-Protection header missing (legacy browsers).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "Cache-Control": {
        "severity": "low",
        "description": "Cache-Control header missing. Sensitive responses may be cached by proxies or browsers.",
        "recommendation": "Add: Cache-Control: no-store for sensitive pages."
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "description": "COOP header missing. May allow cross-origin window references (Spectre mitigation).",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "description": "CORP header missing. Resources may be embedded by other origins.",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-site"
    },
}

DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"
]


class HeaderAnalyzer:
    def __init__(self, target: str):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.findings = []

    def fetch_headers(self) -> dict:
        try:
            response = requests.get(
                self.target,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "CyberScout-Scanner/2.0 (Security Audit)"},
                verify=False
            )
            logger.info(f"Fetched headers from {self.target} — Status: {response.status_code}")
            return dict(response.headers)
        except requests.exceptions.SSLError:
            logger.warning(f"SSL error on {self.target}, retrying over HTTP...")
            http_target = self.target.replace("https://", "http://")
            try:
                response = requests.get(http_target, timeout=10, allow_redirects=True)
                return dict(response.headers)
            except Exception as e:
                logger.error(f"HTTP fallback failed: {e}")
                return {}
        except Exception as e:
            logger.error(f"Failed to fetch headers: {e}")
            return {}

    def check_security_headers(self, headers: dict):
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower not in lower_headers:
                self.findings.append({
                    "module": "headers",
                    "severity": meta["severity"],
                    "title": f"Missing Security Header: {header}",
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                    "evidence": f"Header '{header}' not found in response."
                })
            else:
                value = lower_headers[header_lower]
                # Misconfiguration checks
                issues = self._check_header_value(header, value)
                if issues:
                    for issue in issues:
                        self.findings.append(issue)
                else:
                    self.findings.append({
                        "module": "headers",
                        "severity": "info",
                        "title": f"Header Present: {header}",
                        "description": f"Security header '{header}' is configured.",
                        "recommendation": "Verify the header value meets your security policy.",
                        "evidence": f"{header}: {value[:120]}"
                    })

    def _check_header_value(self, header: str, value: str) -> list:
        """Return list of misconfig findings for a present header, or [] if OK."""
        issues = []

        if header == "Content-Security-Policy":
            if "unsafe-inline" in value:
                issues.append({
                    "module": "headers",
                    "severity": "medium",
                    "title": "CSP Contains 'unsafe-inline'",
                    "description": "CSP is present but allows unsafe-inline scripts/styles, weakening XSS protection.",
                    "recommendation": "Remove 'unsafe-inline' from CSP. Use nonces or hashes instead.",
                    "evidence": f"Content-Security-Policy: {value[:120]}"
                })
            if "unsafe-eval" in value:
                issues.append({
                    "module": "headers",
                    "severity": "medium",
                    "title": "CSP Contains 'unsafe-eval'",
                    "description": "CSP allows eval(), which can be exploited to execute arbitrary code.",
                    "recommendation": "Remove 'unsafe-eval' and refactor code to avoid eval usage.",
                    "evidence": f"Content-Security-Policy: {value[:120]}"
                })

        elif header == "Strict-Transport-Security":
            match = re.search(r"max-age=(\d+)", value)
            if match:
                age = int(match.group(1))
                if age < 31536000:
                    issues.append({
                        "module": "headers",
                        "severity": "medium",
                        "title": "HSTS max-age Too Short",
                        "description": f"HSTS max-age is {age} seconds (less than 1 year). HSTS preload requires ≥1 year.",
                        "recommendation": "Set max-age=31536000 (1 year) or higher.",
                        "evidence": f"Strict-Transport-Security: {value}"
                    })

        elif header == "X-Frame-Options":
            if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
                issues.append({
                    "module": "headers",
                    "severity": "medium",
                    "title": "X-Frame-Options Value Invalid",
                    "description": f"X-Frame-Options has unrecognized value: '{value}'. Must be DENY or SAMEORIGIN.",
                    "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
                    "evidence": f"X-Frame-Options: {value}"
                })

        return issues

    def check_disclosure_headers(self, headers: dict):
        for header in DISCLOSURE_HEADERS:
            value = next((v for k, v in headers.items() if k.lower() == header.lower()), None)
            if value:
                self.findings.append({
                    "module": "headers",
                    "severity": "medium",
                    "title": f"Server Information Disclosure: {header}",
                    "description": (
                        f"The '{header}' header reveals server technology: '{value}'. "
                        "Attackers can use version info to find matching CVEs."
                    ),
                    "recommendation": f"Remove or mask the '{header}' header in your web server configuration.",
                    "evidence": f"{header}: {value}"
                })

    def check_cors(self, headers: dict):
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()
            severity = "critical" if acac == "true" else "high"
            self.findings.append({
                "module": "headers",
                "severity": severity,
                "title": "Overly Permissive CORS Policy" + (" with Credentials" if acac == "true" else ""),
                "description": (
                    "Access-Control-Allow-Origin: * allows any website to make cross-origin requests. "
                    + ("Combined with Allow-Credentials: true, this is a critical misconfiguration." if acac == "true" else "")
                ),
                "recommendation": "Restrict CORS to trusted domains. Never combine wildcard with credentials.",
                "evidence": f"Access-Control-Allow-Origin: {acao}"
                           + (f" | Allow-Credentials: {acac}" if acac else "")
            })

    def check_cookie_security(self, headers: dict):
        """Check Set-Cookie headers for missing security flags."""
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                cookie_name = v.split("=")[0].strip()
                issues = []
                if "httponly" not in v.lower():
                    issues.append("HttpOnly flag missing (JS can read this cookie)")
                if "secure" not in v.lower():
                    issues.append("Secure flag missing (cookie sent over HTTP)")
                if "samesite" not in v.lower():
                    issues.append("SameSite flag missing (CSRF risk)")
                if issues:
                    self.findings.append({
                        "module": "headers",
                        "severity": "medium",
                        "title": f"Insecure Cookie: {cookie_name}",
                        "description": "Cookie missing security flags: " + "; ".join(issues),
                        "recommendation": "Set HttpOnly, Secure, and SameSite=Strict/Lax on all cookies.",
                        "evidence": f"Set-Cookie: {v[:100]}"
                    })

    def run(self) -> list:
        logger.info(f"Starting header analysis on {self.target}")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = self.fetch_headers()

        if not headers:
            return [{
                "module": "headers",
                "severity": "critical",
                "title": "Target Unreachable",
                "description": f"Could not connect to {self.target}.",
                "recommendation": "Verify the target URL and network connectivity.",
                "evidence": f"Target: {self.target}"
            }]

        self.check_security_headers(headers)
        self.check_disclosure_headers(headers)
        self.check_cors(headers)
        self.check_cookie_security(headers)

        logger.info(f"Header analysis complete: {len(self.findings)} findings")
        return self.findings

"""
scanner/xss_tester.py
Tests for Reflected, Stored, and DOM-based XSS vulnerabilities.
Upgraded: stored XSS check, DOM sink detection, context-bypass payloads.
"""

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from utils.logger import setup_logger

logger = setup_logger("xss_tester")

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    '"><img src=x onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',
    # Context-bypass variants
    '</script><script>alert(1)</script>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '%3cscript%3ealert(1)%3c/script%3e',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<video><source onerror=alert(1)>',
    '" onmouseover="alert(1)',
]

# DOM sinks that can lead to XSS
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.assign",
    "location.replace",
    "window.location",
    "document.cookie",
    "insertAdjacentHTML",
]

UNIQUE_MARKER = "CSXSS99Z"  # marker injected to detect stored XSS


class XSSTester:
    def __init__(self, target: str):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberScout-Scanner/2.0"})
        self.findings = []
        self._found: set = set()

    def _add_finding(self, kind, param, url, payload, evidence):
        key = (kind, param)
        if key in self._found:
            return
        self._found.add(key)
        severity = "critical" if kind == "stored" else "high"
        self.findings.append({
            "module": "xss",
            "severity": severity,
            "title": f"{kind.title()} XSS — Parameter: '{param}'",
            "description": (
                f"Input '{param}' at {url} is vulnerable to {kind} Cross-Site Scripting. "
                "An attacker can execute arbitrary JavaScript in victims' browsers."
            ),
            "recommendation": (
                "Encode all output with HTML entity encoding. "
                "Implement a strict Content-Security-Policy. "
                "Validate and sanitize all user inputs server-side. "
                "Use a security-aware templating engine."
            ),
            "evidence": evidence
        })

    def get_forms(self) -> list:
        try:
            import urllib3; urllib3.disable_warnings()
            resp = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            logger.warning(f"Failed to fetch page: {e}")
            return []

    def extract_form_data(self, form) -> tuple:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(self.target, action) if action else self.target
        inputs = {}
        for tag in form.find_all(["input", "textarea"]):
            name = tag.get("name")
            itype = tag.get("type", "text")
            if name and itype not in ("submit", "button", "hidden", "file"):
                inputs[name] = "test"
        return action_url, method, inputs

    def check_reflection(self, text: str, payload: str) -> bool:
        return payload in text or payload.lower() in text.lower()

    # ── Reflected XSS ────────────────────────────────────────────────────────

    def test_form_xss(self, action_url, method, inputs):
        for param in inputs:
            for payload in XSS_PAYLOADS:
                data = inputs.copy()
                data[param] = payload
                try:
                    if method == "post":
                        resp = self.session.post(action_url, data=data, timeout=10, verify=False)
                    else:
                        resp = self.session.get(action_url, params=data, timeout=10, verify=False)

                    if self.check_reflection(resp.text, payload):
                        self._add_finding(
                            "reflected", param, action_url, payload,
                            f"Payload reflected verbatim in response. Payload: {payload[:60]}"
                        )
                        break
                except Exception as e:
                    logger.debug(f"XSS form test error: {e}")

    def test_url_xss(self):
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = self.target.split("?")[0] + "?" + urlencode(test_params)
                try:
                    resp = self.session.get(test_url, timeout=10, verify=False)
                    if self.check_reflection(resp.text, payload):
                        self._add_finding(
                            "reflected", param, test_url, payload,
                            f"URL param reflects payload. URL: {test_url[:80]} | Payload: {payload[:50]}"
                        )
                        break
                except Exception as e:
                    logger.debug(f"URL XSS test error: {e}")

    # ── Stored XSS ───────────────────────────────────────────────────────────

    def test_stored_xss(self, forms):
        """
        Inject a unique marker via POST forms, then GET the page again
        and check if the marker appears in the response (stored).
        """
        stored_payload = f'<script>alert("{UNIQUE_MARKER}")</script>'

        for form in forms:
            action_url, method, inputs = self.extract_form_data(form)
            if method != "post" or not inputs:
                continue

            data = {k: stored_payload for k in inputs}
            try:
                self.session.post(action_url, data=data, timeout=10, verify=False)
                # Re-fetch the page to check if marker persisted
                resp = self.session.get(self.target, timeout=10, verify=False)
                if UNIQUE_MARKER in resp.text:
                    param_list = ", ".join(inputs.keys())
                    self._add_finding(
                        "stored", param_list, action_url, stored_payload,
                        f"Marker '{UNIQUE_MARKER}' persisted in GET response after POST to {action_url}"
                    )
            except Exception as e:
                logger.debug(f"Stored XSS test error: {e}")

    # ── DOM-based detection ──────────────────────────────────────────────────

    def test_dom_xss(self):
        """
        Fetch the page source and scan for dangerous DOM sinks.
        This is a static analysis pass — it flags potential DOM XSS locations.
        """
        try:
            resp = self.session.get(self.target, timeout=10, verify=False)
            source = resp.text

            for sink in DOM_SINKS:
                if sink in source:
                    # Find surrounding context
                    idx = source.find(sink)
                    snippet = source[max(0, idx - 40): idx + len(sink) + 40].strip()
                    snippet = re.sub(r"\s+", " ", snippet)

                    key = ("dom", sink)
                    if key not in self._found:
                        self._found.add(key)
                        self.findings.append({
                            "module": "xss",
                            "severity": "medium",
                            "title": f"Potential DOM XSS Sink: {sink}",
                            "description": (
                                f"JavaScript source uses '{sink}', a common DOM XSS sink. "
                                "If user-controlled data flows into this sink, DOM-based XSS is possible."
                            ),
                            "recommendation": (
                                "Review all uses of this sink. "
                                "Avoid assigning untrusted data to innerHTML/outerHTML/eval. "
                                "Use textContent instead of innerHTML where possible."
                            ),
                            "evidence": f"Sink: {sink} | Context: ...{snippet}..."
                        })
        except Exception as e:
            logger.debug(f"DOM XSS scan error: {e}")

    def run(self) -> list:
        logger.info(f"Starting XSS tests on {self.target}")
        import urllib3; urllib3.disable_warnings()

        forms = self.get_forms()

        for form in forms:
            action_url, method, inputs = self.extract_form_data(form)
            if inputs:
                self.test_form_xss(action_url, method, inputs)

        self.test_url_xss()
        self.test_stored_xss(forms)
        self.test_dom_xss()

        if not self.findings:
            self.findings.append({
                "module": "xss",
                "severity": "info",
                "title": "No XSS Detected",
                "description": (
                    "No reflected, stored, or DOM-based XSS was detected. "
                    "Automated testing covers common vectors but cannot guarantee full coverage."
                ),
                "recommendation": "Perform manual testing and review all JavaScript sinks in source code.",
                "evidence": f"Tested {len(XSS_PAYLOADS)} payloads on {len(forms)} form(s), "
                            f"URL params, stored probe, and {len(DOM_SINKS)} DOM sinks."
            })

        return self.findings

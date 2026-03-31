"""
scanner/ssl_inspector.py
Full SSL/TLS inspection: cert validity, cipher strength, protocol version,
HSTS preload check, SAN validation, wildcard warning, tiered expiry alerts.
"""

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
from utils.logger import setup_logger

logger = setup_logger("ssl_inspector")

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS   = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"]


class SSLInspector:
    def __init__(self, target: str):
        parsed = urlparse(target if "://" in target else f"https://{target}")
        self.host = parsed.hostname or target
        self.port = parsed.port or 443
        self.target = target if target.startswith("http") else f"https://{target}"
        self.findings = []

    def get_cert_info(self) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.host, self.port), timeout=10),
                server_hostname=self.host
            ) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()
                return {
                    "cert":         cert,
                    "cipher_name":  cipher[0] if cipher else "unknown",
                    "cipher_bits":  cipher[2] if cipher else 0,
                    "protocol":     proto
                }
        except ssl.SSLCertVerificationError as e:
            logger.warning(f"SSL cert verification failed: {e}")
            return {"error": "cert_verification", "detail": str(e)}
        except Exception as e:
            logger.error(f"SSL connection failed: {e}")
            return None

    # ── Certificate checks ───────────────────────────────────────────────────

    def check_expiry(self, cert: dict):
        not_after = cert.get("notAfter", "")
        if not not_after:
            return
        try:
            expiry    = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days

            if days_left < 0:
                self.findings.append({
                    "module": "ssl", "severity": "critical",
                    "title": "SSL Certificate EXPIRED",
                    "description": f"Certificate expired {abs(days_left)} days ago on {not_after}.",
                    "recommendation": "Renew immediately. Use Let's Encrypt for free auto-renewal.",
                    "evidence": f"Expiry: {not_after}"
                })
            elif days_left < 14:
                self.findings.append({
                    "module": "ssl", "severity": "critical",
                    "title": f"Certificate Expiring in {days_left} Days — CRITICAL",
                    "description": f"Certificate expires {not_after}. Imminent risk of browser warnings and outage.",
                    "recommendation": "Renew SSL certificate within 24 hours.",
                    "evidence": f"Days remaining: {days_left}"
                })
            elif days_left < 30:
                self.findings.append({
                    "module": "ssl", "severity": "high",
                    "title": f"Certificate Expiring Soon ({days_left} days)",
                    "description": f"SSL certificate expires {not_after}.",
                    "recommendation": "Renew the certificate before expiry.",
                    "evidence": f"Days remaining: {days_left}"
                })
            elif days_left < 90:
                self.findings.append({
                    "module": "ssl", "severity": "medium",
                    "title": f"Certificate Expiring in {days_left} Days",
                    "description": f"Certificate will expire on {not_after}. Plan renewal.",
                    "recommendation": "Schedule certificate renewal within the next 30 days.",
                    "evidence": f"Days remaining: {days_left}"
                })
            else:
                self.findings.append({
                    "module": "ssl", "severity": "info",
                    "title": f"Certificate Valid ({days_left} days remaining)",
                    "description": f"Certificate expires on {not_after}.",
                    "recommendation": "Set up automated renewal alerts at 30-day threshold.",
                    "evidence": f"Expiry: {not_after}"
                })
        except ValueError as e:
            logger.warning(f"Could not parse cert expiry: {e}")

    def check_self_signed(self, cert: dict):
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject == issuer:
            self.findings.append({
                "module": "ssl", "severity": "high",
                "title": "Self-Signed Certificate Detected",
                "description": "Certificate is self-signed. Browsers will display security warnings.",
                "recommendation": "Replace with a certificate from a trusted CA (e.g., Let's Encrypt, DigiCert).",
                "evidence": f"Subject == Issuer: {subject.get('commonName', 'unknown')}"
            })

    def check_san(self, cert: dict):
        """Validate Subject Alternative Names include the queried host."""
        san_list = []
        for ext_type, ext_data in cert.get("subjectAltName", []):
            if ext_type == "DNS":
                san_list.append(ext_data.lower())

        if not san_list:
            self.findings.append({
                "module": "ssl", "severity": "medium",
                "title": "No Subject Alternative Names (SANs)",
                "description": "Certificate has no SANs. Modern browsers require SANs; CN-only certs are rejected.",
                "recommendation": "Reissue certificate with proper SAN entries.",
                "evidence": f"subjectAltName field empty"
            })
            return

        host_lower = self.host.lower()
        matched = any(
            san == host_lower or
            (san.startswith("*.") and host_lower.endswith(san[1:]))
            for san in san_list
        )
        if not matched:
            self.findings.append({
                "module": "ssl", "severity": "high",
                "title": "Certificate Hostname Mismatch",
                "description": f"Certificate SANs {san_list} do not match queried host '{self.host}'.",
                "recommendation": "Reissue certificate to include the correct hostname.",
                "evidence": f"Host: {self.host} | SANs: {', '.join(san_list[:5])}"
            })

        # Wildcard warning
        for san in san_list:
            if san.startswith("*."):
                self.findings.append({
                    "module": "ssl", "severity": "low",
                    "title": f"Wildcard Certificate in Use: {san}",
                    "description": (
                        "Wildcard certs cover all subdomains. If the private key is compromised, "
                        "all subdomains are affected."
                    ),
                    "recommendation": (
                        "Consider per-subdomain certificates for high-value services. "
                        "Rotate wildcard certs immediately if key compromise is suspected."
                    ),
                    "evidence": f"SAN: {san}"
                })
            break  # Report first wildcard only

    # ── Cipher / protocol checks ─────────────────────────────────────────────

    def check_cipher(self, cipher_name: str, cipher_bits: int, protocol: str):
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                self.findings.append({
                    "module": "ssl", "severity": "high",
                    "title": f"Weak Cipher Suite: {cipher_name}",
                    "description": f"Cipher '{cipher_name}' is cryptographically weak ({weak}).",
                    "recommendation": "Configure server to accept only AES-256-GCM or ChaCha20 suites.",
                    "evidence": f"Cipher: {cipher_name} | Bits: {cipher_bits}"
                })
                return

        if cipher_bits and cipher_bits < 128:
            self.findings.append({
                "module": "ssl", "severity": "high",
                "title": f"Insufficient Key Length: {cipher_bits} bits",
                "description": "Cipher key length below 128 bits is considered insecure.",
                "recommendation": "Use minimum 128-bit (preferably 256-bit) encryption.",
                "evidence": f"Cipher: {cipher_name} | Bits: {cipher_bits}"
            })
        else:
            self.findings.append({
                "module": "ssl", "severity": "info",
                "title": f"Strong Cipher: {cipher_name} ({cipher_bits}-bit)",
                "description": f"Negotiated cipher via {protocol}.",
                "recommendation": "Periodically review cipher suite config as standards evolve.",
                "evidence": f"Cipher: {cipher_name} | Bits: {cipher_bits} | Protocol: {protocol}"
            })

        if protocol in WEAK_PROTOCOLS:
            self.findings.append({
                "module": "ssl", "severity": "critical",
                "title": f"Weak TLS Protocol: {protocol}",
                "description": f"Protocol {protocol} has known vulnerabilities (POODLE, BEAST, etc.).",
                "recommendation": "Disable TLS 1.0 and 1.1. Require TLS 1.2 or TLS 1.3 only.",
                "evidence": f"Negotiated protocol: {protocol}"
            })

    # ── HSTS preload check ───────────────────────────────────────────────────

    def check_hsts_preload(self):
        """Check if HSTS header has the preload directive and meets preload requirements."""
        try:
            resp = requests.get(self.target, timeout=10, verify=False)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                if "preload" not in hsts:
                    self.findings.append({
                        "module": "ssl", "severity": "low",
                        "title": "HSTS Missing Preload Directive",
                        "description": "HSTS header present but lacks the 'preload' directive.",
                        "recommendation": "Add 'preload' to HSTS and submit to hstspreload.org.",
                        "evidence": f"Strict-Transport-Security: {hsts}"
                    })
                if "includesubdomains" not in hsts.lower():
                    self.findings.append({
                        "module": "ssl", "severity": "low",
                        "title": "HSTS Missing includeSubDomains",
                        "description": "HSTS does not cover subdomains, leaving them vulnerable to downgrade.",
                        "recommendation": "Add 'includeSubDomains' to the HSTS header.",
                        "evidence": f"Strict-Transport-Security: {hsts}"
                    })
        except Exception as e:
            logger.debug(f"HSTS preload check failed: {e}")

    def run(self) -> list:
        logger.info(f"Starting SSL inspection on {self.host}:{self.port}")
        import urllib3; urllib3.disable_warnings()

        if self.port != 443:
            self.findings.append({
                "module": "ssl", "severity": "info",
                "title": "Non-standard HTTPS Port",
                "description": f"Target using port {self.port} instead of 443.",
                "recommendation": "Verify this is intentional.",
                "evidence": f"Port: {self.port}"
            })

        info = self.get_cert_info()

        if info is None:
            self.findings.append({
                "module": "ssl", "severity": "critical",
                "title": "SSL Connection Failed",
                "description": f"Could not establish SSL/TLS connection to {self.host}:{self.port}.",
                "recommendation": "Verify the server supports HTTPS and is reachable.",
                "evidence": f"Host: {self.host}:{self.port}"
            })
            return self.findings

        if "error" in info:
            self.findings.append({
                "module": "ssl", "severity": "critical",
                "title": "SSL Certificate Verification Failed",
                "description": f"Certificate could not be verified: {info.get('detail', '')}",
                "recommendation": "Use a certificate from a trusted Certificate Authority.",
                "evidence": info.get("detail", "")
            })
            return self.findings

        cert = info["cert"]
        self.check_expiry(cert)
        self.check_self_signed(cert)
        self.check_san(cert)
        self.check_cipher(info["cipher_name"], info["cipher_bits"], info["protocol"])
        self.check_hsts_preload()

        return self.findings

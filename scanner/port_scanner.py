"""
scanner/port_scanner.py
Multi-threaded TCP port scanner with service fingerprinting, CVE hints,
OS-level risk descriptions, and banner grabbing.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from utils.logger import setup_logger

logger = setup_logger("port_scanner")

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    2049:  "NFS",
    2375:  "Docker-HTTP",
    2376:  "Docker-TLS",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit-Default",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter-Notebook",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Alt",
}

# severity, description, CVE hints, OS risk note
RISKY_PORTS = {
    21: {
        "severity": "high",
        "description": "FTP transmits credentials in plaintext. Anonymous access may be enabled.",
        "cve_hints": ["CVE-2010-4221 (ProFTPD mod_sql)", "CVE-2015-3306 (ProFTPD mod_copy)"],
        "os_risk": "Linux/Windows — default FTP daemons often misconfigured."
    },
    23: {
        "severity": "critical",
        "description": "Telnet is unencrypted. All traffic including passwords visible in plaintext.",
        "cve_hints": ["CVE-2001-0554 (BSD Telnet overflow)"],
        "os_risk": "Legacy systems. Disable immediately and replace with SSH."
    },
    445: {
        "severity": "critical",
        "description": "SMB — primary vector for EternalBlue / WannaCry ransomware.",
        "cve_hints": ["CVE-2017-0144 (EternalBlue / WannaCry)", "CVE-2020-0796 (SMBGhost)"],
        "os_risk": "Windows — ensure SMBv1 is disabled. Patch MS17-010."
    },
    1433: {
        "severity": "high",
        "description": "MSSQL exposed. Risk of credential brute force and SQL-injection-to-RCE.",
        "cve_hints": ["CVE-2000-0402 (MSSQL extended procedures)"],
        "os_risk": "Windows — restrict to localhost or VPN only."
    },
    2375: {
        "severity": "critical",
        "description": "Docker daemon API exposed without TLS. Full container escape possible.",
        "cve_hints": ["CVE-2019-5736 (runc escape)", "CVE-2020-15257 (containerd escape)"],
        "os_risk": "Linux — unauthenticated Docker API = root on host. Block immediately."
    },
    3306: {
        "severity": "high",
        "description": "MySQL exposed externally. Brute force and direct DB access risk.",
        "cve_hints": ["CVE-2012-2122 (MySQL auth bypass)"],
        "os_risk": "Linux/Windows — bind to 127.0.0.1 unless replication is required."
    },
    3389: {
        "severity": "high",
        "description": "RDP exposed — brute force and BlueKeep exploitation target.",
        "cve_hints": ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1182 (DejaBlue)"],
        "os_risk": "Windows — enable NLA, restrict by IP, use VPN for remote access."
    },
    4444: {
        "severity": "critical",
        "description": "Port 4444 is the Metasploit default listener port. Possible active compromise.",
        "cve_hints": [],
        "os_risk": "Any — investigate immediately for signs of compromise."
    },
    5900: {
        "severity": "high",
        "description": "VNC remote desktop exposed. Often runs without auth or with weak passwords.",
        "cve_hints": ["CVE-2019-15681 (LibVNCServer info leak)"],
        "os_risk": "Linux/Windows — restrict to VPN, enable VNC authentication."
    },
    6379: {
        "severity": "critical",
        "description": "Redis exposed without authentication. Full data read/write and potential RCE.",
        "cve_hints": ["CVE-2022-0543 (Redis Lua sandbox escape)"],
        "os_risk": "Linux — Redis should bind to 127.0.0.1 with requirepass set."
    },
    8888: {
        "severity": "high",
        "description": "Jupyter Notebook exposed — may allow unauthenticated code execution.",
        "cve_hints": [],
        "os_risk": "Linux — Jupyter should never be internet-facing without authentication."
    },
    9200: {
        "severity": "high",
        "description": "Elasticsearch HTTP API exposed. Data exfiltration risk without auth.",
        "cve_hints": ["CVE-2015-1427 (Groovy script RCE)"],
        "os_risk": "Linux — enable X-Pack security, restrict to internal network."
    },
    11211: {
        "severity": "high",
        "description": "Memcached exposed — DDoS amplification vector and data leakage.",
        "cve_hints": ["CVE-2018-1000115 (UDP amplification)"],
        "os_risk": "Linux — bind to 127.0.0.1, disable UDP support."
    },
    27017: {
        "severity": "critical",
        "description": "MongoDB exposed without authentication — common misconfiguration.",
        "cve_hints": ["CVE-2013-3969 (NoSQL injection)"],
        "os_risk": "Linux — enable --auth, bind to 127.0.0.1."
    },
}


class PortScanner:
    def __init__(self, target: str, port_range: tuple = (1, 1024),
                 timeout: float = 0.5, max_threads: int = 200):
        parsed = urlparse(target if "://" in target else f"https://{target}")
        self.host        = parsed.hostname or target
        self.port_range  = port_range
        self.timeout     = timeout
        self.max_threads = max_threads
        self.open_ports  = []
        self.lock        = threading.Lock()

    def resolve_host(self) -> str:
        try:
            ip = socket.gethostbyname(self.host)
            logger.info(f"Resolved {self.host} -> {ip}")
            return ip
        except socket.gaierror as e:
            logger.error(f"Could not resolve hostname: {self.host} — {e}")
            return self.host

    def scan_port(self, ip: str, port: int) -> dict | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((ip, port)) == 0:
                    banner = self.grab_banner(ip, port)
                    return {"port": port, "service": banner}
        except Exception:
            pass
        return None

    def grab_banner(self, ip: str, port: int) -> str:
        known = COMMON_PORTS.get(port, "unknown")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((ip, port))
                if port not in (80, 443, 8080, 8443):
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(512).decode("utf-8", errors="ignore").strip()
                first_line = banner.splitlines()[0][:60] if banner else ""
                if first_line:
                    return f"{known} ({first_line})"
        except Exception:
            pass
        return known

    def run(self) -> list:
        ip = self.resolve_host()
        findings = []
        start, end = self.port_range

        logger.info(f"Scanning {self.host} ({ip}) ports {start}-{end}")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, ip, p): p for p in range(start, end + 1)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.open_ports.append(result)

        self.open_ports.sort(key=lambda x: x["port"])

        for entry in self.open_ports:
            port    = entry["port"]
            service = entry["service"]
            risk    = RISKY_PORTS.get(port)

            if risk:
                cve_text = (
                    " Relevant CVEs: " + ", ".join(risk["cve_hints"])
                    if risk["cve_hints"] else ""
                )
                findings.append({
                    "module": "ports",
                    "severity": risk["severity"],
                    "title": f"Open Risky Port {port}/{COMMON_PORTS.get(port, 'unknown')} — {risk['severity'].upper()} Risk",
                    "description": (
                        f"{risk['description']}"
                        f"{cve_text}"
                    ),
                    "recommendation": (
                        f"OS note: {risk['os_risk']} "
                        f"Restrict port {port} via firewall. Expose only to authorized IPs."
                    ),
                    "evidence": f"{ip}:{port} — Banner: {service}"
                })
            else:
                findings.append({
                    "module": "ports",
                    "severity": "info",
                    "title": f"Open Port {port}/{COMMON_PORTS.get(port, service)}",
                    "description": f"Port {port} is open and running {service}.",
                    "recommendation": "Verify this service is intentionally exposed to the internet.",
                    "evidence": f"{ip}:{port} — {service}"
                })

        findings.append({
            "module": "ports",
            "severity": "info",
            "title": "Port Scan Summary",
            "description": f"Scanned ports {start}–{end} on {self.host}. Found {len(self.open_ports)} open port(s).",
            "recommendation": "Close or firewall all non-essential ports.",
            "evidence": ", ".join(str(p["port"]) for p in self.open_ports) or "No open ports found"
        })

        return findings

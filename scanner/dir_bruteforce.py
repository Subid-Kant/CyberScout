"""
scanner/dir_bruteforce.py
Directory/file enumeration with 100+ paths, severity tiers,
and second-pass backup extension check (.bak, .old, ~, .swp).
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger

logger = setup_logger("dir_bruteforce")

DEFAULT_WORDLIST = [
    # Admin panels
    "admin", "admin/", "admin/login", "admin/dashboard", "administrator",
    "administrator/", "admin.php", "admin.html", "adminpanel", "wp-admin",
    "wp-admin/", "wp-login.php", "panel", "cpanel", "manage", "management",
    "console", "control", "controlpanel", "backend", "adm",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/users", "api/admin",
    "api/config", "api/debug", "graphql", "swagger", "swagger-ui",
    "swagger-ui.html", "openapi.json", "api-docs", "rest",
    # Auth
    "login", "login.php", "logout", "register", "signup", "signin",
    "forgot", "reset-password", "auth", "oauth", "oauth/callback",
    "sso", "token", "verify", "activate",
    # User
    "user", "users", "profile", "account", "accounts", "dashboard",
    "portal", "me", "settings",
    # Config / secrets
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    "config", "config.php", "config.json", "config.yml", "config.yaml",
    "configuration", "settings", "settings.php", "settings.py",
    "web.config", ".htaccess", ".htpasswd", "local.xml",
    # DB / backup
    "db", "database", "db.sql", "dump.sql", "backup.sql", "backup.zip",
    "backup", "db_backup", "database_backup", "sql", "phpmyadmin",
    "pma", "myadmin", "dbadmin",
    # Dev / debug
    "debug", "test", "test.php", "dev", "development", "staging", "qa",
    "phpinfo.php", "info.php", "php.php", "test.html", "demo",
    "trace", "error", "errors", "exception", "diagnostics",
    # Shell / exploit
    "shell.php", "cmd.php", "eval.php", "c99.php", "r57.php",
    "webshell.php", "hack.php", "backdoor.php", "upload.php",
    # Git / VCS
    ".git", ".git/config", ".git/HEAD", ".gitignore", ".gitmodules",
    ".svn", ".svn/entries", ".hg", ".hgignore",
    # Logs
    "logs", "log", "access.log", "error.log", "debug.log",
    "application.log", "server.log",
    # Files / uploads
    "upload", "uploads", "files", "file", "media", "attachments",
    "images", "img", "static", "assets", "public",
    # Tech specific
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    "cgi-bin", "scripts", "bin", "proc",
    # Cloud
    ".aws/credentials", ".aws/config", ".gcloud",
    # Node / JS
    "node_modules", "package.json", "package-lock.json", "yarn.lock",
    ".npmrc", ".nvmrc",
    # Python
    "requirements.txt", "Pipfile", "pyproject.toml", "manage.py",
    # Java
    "WEB-INF", "WEB-INF/web.xml", "META-INF", "actuator",
    "actuator/health", "actuator/env", "actuator/dump",
    # Misc
    "old", "bak", "backup2", "src", "source", "include", "includes",
    "lib", "vendor", "secret", "private", "hidden", "internal",
    "health", "status", "metrics", "ping", "version", "changelog",
]

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".copy", "~", ".swp", ".save", ".1"]

SEVERITY_MAP = {
    # Critical
    ".git": "critical", ".git/config": "critical", ".git/HEAD": "critical",
    ".env": "critical", ".env.local": "critical", ".env.production": "critical",
    ".env.staging": "critical", ".env.backup": "critical",
    "shell.php": "critical", "cmd.php": "critical", "eval.php": "critical",
    "c99.php": "critical", "r57.php": "critical", "webshell.php": "critical",
    "hack.php": "critical", "backdoor.php": "critical",
    ".aws/credentials": "critical", ".htpasswd": "critical",
    "2375": "critical",
    # High
    "phpinfo.php": "high", "info.php": "high", "phpmyadmin": "high",
    "pma": "high", "myadmin": "high", "dbadmin": "high",
    "web.config": "high", "config.php": "high", "config.json": "high",
    "backup": "high", "backup.sql": "high", "dump.sql": "high",
    "db": "high", "database": "high", "sql": "high",
    "actuator/env": "high", "actuator/dump": "high",
    "WEB-INF/web.xml": "high", ".git/config": "high",
    "access.log": "high", "error.log": "high",
    # Medium
    "admin": "medium", "administrator": "medium", "wp-admin": "medium",
    "wp-login.php": "medium", "panel": "medium", "cpanel": "medium",
    "console": "medium", "logs": "medium", "upload": "medium",
    "uploads": "medium", ".htaccess": "medium",
    "swagger": "medium", "graphql": "medium", "api/admin": "medium",
    "actuator": "medium", "actuator/health": "medium",
}


class DirBruteforcer:
    def __init__(self, target: str, wordlist: list = None,
                 max_threads: int = 20, timeout: float = 5.0):
        self.target = target.rstrip("/")
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"
        self.wordlist    = wordlist or DEFAULT_WORDLIST
        self.max_threads = max_threads
        self.timeout     = timeout
        self.session     = requests.Session()
        self.session.headers.update({"User-Agent": "CyberScout-Scanner/2.0"})
        self.session.verify = False
        self.findings    = []
        import urllib3; urllib3.disable_warnings()

    def probe(self, path: str) -> dict | None:
        url = f"{self.target}/{path}"
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code in (200, 201, 204, 301, 302, 403):
                return {
                    "path":   path,
                    "url":    url,
                    "status": resp.status_code,
                    "size":   len(resp.content)
                }
        except Exception:
            pass
        return None

    def _bulk_probe(self, paths: list) -> list:
        discovered = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.probe, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        return discovered

    def run(self) -> list:
        logger.info(f"Starting dir bruteforce on {self.target} ({len(self.wordlist)} paths)")

        # Pass 1: standard wordlist
        discovered = self._bulk_probe(self.wordlist)

        # Pass 2: backup extensions on discovered paths
        backup_paths = []
        for item in discovered:
            path = item["path"]
            if "." in path.split("/")[-1]:  # e.g. config.php → config.php.bak
                for ext in BACKUP_EXTENSIONS:
                    backup_paths.append(path + ext)
            else:  # e.g. config → config.bak
                for ext in BACKUP_EXTENSIONS:
                    backup_paths.append(path + ext)

        if backup_paths:
            logger.info(f"Pass 2: checking {len(backup_paths)} backup extension variants")
            backup_hits = self._bulk_probe(backup_paths)
            discovered.extend(backup_hits)

        for item in sorted(discovered, key=lambda x: x["path"]):
            path     = item["path"]
            status   = item["status"]
            url      = item["url"]
            severity = SEVERITY_MAP.get(path, "low")

            # Backup files are always high if found
            if any(path.endswith(ext) for ext in BACKUP_EXTENSIONS):
                severity = "high"
                description = (
                    f"Backup file '/{path}' is publicly accessible. "
                    "These files often contain credentials, database configs, or source code."
                )
            elif severity == "critical":
                description = (
                    f"CRITICAL path '/{path}' is accessible. "
                    "This may expose credentials, source code, or allow remote code execution."
                )
            elif severity == "high":
                description = (
                    f"High-risk path '/{path}' accessible (HTTP {status}). "
                    "Review access controls immediately."
                )
            elif status == 403:
                description = f"Path '/{path}' exists but access is forbidden (403). Server confirmed its existence."
                severity    = "low"
            else:
                description = f"Path '/{path}' returned HTTP {status}. Verify this is intentionally public."

            self.findings.append({
                "module": "dirs",
                "severity": severity,
                "title": f"Discovered: /{path} [{status}]",
                "description": description,
                "recommendation": (
                    "Remove or restrict access to sensitive paths. "
                    ".git, .env, backup files, and admin panels must never be publicly accessible."
                ),
                "evidence": f"URL: {url} | HTTP {status} | Size: {item['size']} bytes"
            })

        if not self.findings:
            self.findings.append({
                "module": "dirs",
                "severity": "info",
                "title": "No Sensitive Directories Found",
                "description": f"Probed {len(self.wordlist)} paths + backup extensions. Nothing accessible.",
                "recommendation": "Expand wordlist for deeper coverage and test authenticated paths.",
                "evidence": f"Tested {len(self.wordlist)} primary + backup extension variants on {self.target}"
            })

        return self.findings

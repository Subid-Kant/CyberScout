"""
app.py
CyberScout — Production-ready Flask application.
Features: auth, DB scan history, rate limiting, all scanner modules.
"""

import uuid
import threading
import datetime
import argparse

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy

from models import db, User, ScanHistory, Finding
from auth import auth_bp, login_required, current_user
from rate_limiter import scan_limiter
from scanner.header_check import HeaderAnalyzer
from scanner.port_scanner import PortScanner
from scanner.sqli_tester import SQLiTester
from scanner.xss_tester import XSSTester
from scanner.ssl_inspector import SSLInspector
from scanner.dir_bruteforce import DirBruteforcer
from scanner.report_gen import ReportGenerator
from utils.logger import setup_logger
from utils.helpers import calculate_risk_score, is_valid_target

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"]           = "change-me-in-production-use-env-var"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cyberscout.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(hours=8)

db.init_app(app)
app.register_blueprint(auth_bp)

logger = setup_logger("cyberscout")

# In-memory scan state (supplement to DB for live progress)
scan_status:  dict = {}
scan_results: dict = {}


# ── DB init ──────────────────────────────────────────────────────────────────

@app.before_request
def create_tables():
    db.create_all()


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


# ── Scan API ──────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@scan_limiter.limit(max_calls=5, period=60)
def start_scan():
    data    = request.get_json() or {}
    target  = data.get("target", "").strip()
    modules = data.get("modules", [])
    scan_id = data.get("scan_id") or str(uuid.uuid4())[:8]

    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target URL"}), 400
    if not modules:
        return jsonify({"error": "Select at least one module"}), 400

    # Persist to DB
    user   = current_user()
    record = ScanHistory(
        scan_id = scan_id,
        target  = target,
        modules = ",".join(modules),
        status  = "running",
        user_id = user.id if user else None,
    )
    db.session.add(record)
    db.session.commit()
    record_id = record.id

    scan_status[scan_id]  = {"status": "running", "progress": 0, "current": "Initializing..."}
    scan_results[scan_id] = []

    def run_scan():
        findings = []
        total    = len(modules)

        module_map = {
            "headers": lambda: HeaderAnalyzer(target).run(),
            "ports":   lambda: PortScanner(target).run(),
            "sqli":    lambda: SQLiTester(target).run(),
            "xss":     lambda: XSSTester(target).run(),
            "ssl":     lambda: SSLInspector(target).run(),
            "dirs":    lambda: DirBruteforcer(target).run(),
        }

        for i, module in enumerate(modules):
            scan_status[scan_id]["current"]  = f"Running {module}..."
            scan_status[scan_id]["progress"] = int((i / total) * 100)
            logger.info(f"[{scan_id}] Running module: {module} on {target}")

            runner = module_map.get(module)
            if not runner:
                continue
            try:
                results = runner()
                findings.extend(results)
            except Exception as e:
                logger.error(f"[{scan_id}] Error in {module}: {e}")
                findings.append({
                    "module":         module,
                    "severity":       "info",
                    "title":          f"Module error: {module}",
                    "description":    str(e),
                    "recommendation": "Check target connectivity and module configuration.",
                    "evidence":       ""
                })

        scan_results[scan_id] = findings
        scan_status[scan_id]  = {"status": "complete", "progress": 100, "current": "Done"}

        # Persist findings + update scan record
        with app.app_context():
            score  = calculate_risk_score(findings)
            rec    = db.session.get(ScanHistory, record_id)
            if rec:
                rec.status     = "complete"
                rec.risk_score = score
                rec.ended_at   = datetime.datetime.utcnow()
                for f in findings:
                    rec.findings.append(Finding(
                        module         = f.get("module", ""),
                        severity       = f.get("severity", "info"),
                        title          = f.get("title", ""),
                        description    = f.get("description", ""),
                        recommendation = f.get("recommendation", ""),
                        evidence       = f.get("evidence", ""),
                    ))
                db.session.commit()

        logger.info(f"[{scan_id}] Complete — {len(findings)} findings, score={score}")

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

    return jsonify({"scan_id": scan_id, "message": "Scan started"})


@app.route("/api/status/<scan_id>")
def get_status(scan_id):
    return jsonify(scan_status.get(scan_id, {"status": "not_found"}))


@app.route("/api/results/<scan_id>")
def get_results(scan_id):
    results = scan_results.get(scan_id, [])

    # Fall back to DB if not in memory (e.g. after restart)
    if not results:
        rec = ScanHistory.query.filter_by(scan_id=scan_id).first()
        if rec:
            results = [f.to_dict() for f in rec.findings]

    summary = {
        "critical": sum(1 for r in results if r.get("severity") == "critical"),
        "high":     sum(1 for r in results if r.get("severity") == "high"),
        "medium":   sum(1 for r in results if r.get("severity") == "medium"),
        "low":      sum(1 for r in results if r.get("severity") == "low"),
        "info":     sum(1 for r in results if r.get("severity") == "info"),
        "total":    len(results),
        "risk_score": calculate_risk_score(results),
    }
    return jsonify({"findings": results, "summary": summary})


@app.route("/api/report/<scan_id>")
def download_report(scan_id):
    results = scan_results.get(scan_id, [])
    if not results:
        rec = ScanHistory.query.filter_by(scan_id=scan_id).first()
        if rec:
            results = [f.to_dict() for f in rec.findings]

    if not results:
        return jsonify({"error": "No results found for this scan ID"}), 404

    rec    = ScanHistory.query.filter_by(scan_id=scan_id).first()
    target = rec.target if rec else ""
    gen    = ReportGenerator(scan_id, results, target=target)
    filepath = gen.generate()
    return send_file(filepath, as_attachment=True)


# ── Scan history API ──────────────────────────────────────────────────────────

@app.route("/api/history")
@login_required
def scan_history():
    user  = current_user()
    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))

    query = ScanHistory.query
    if not user.is_admin:
        query = query.filter_by(user_id=user.id)

    total = query.count()
    scans = query.order_by(ScanHistory.started_at.desc()) \
                 .offset((page - 1) * limit).limit(limit).all()

    return jsonify({
        "scans":      [s.to_dict() for s in scans],
        "total":      total,
        "page":       page,
        "total_pages": (total + limit - 1) // limit,
    })


@app.route("/api/history/<scan_id>")
@login_required
def scan_history_detail(scan_id):
    rec = ScanHistory.query.filter_by(scan_id=scan_id).first_or_404()
    user = current_user()
    if not user.is_admin and rec.user_id != user.id:
        return jsonify({"error": "Access denied"}), 403
    return jsonify(rec.to_dict(include_findings=True))


@app.route("/api/history/<scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    rec  = ScanHistory.query.filter_by(scan_id=scan_id).first_or_404()
    user = current_user()
    if not user.is_admin and rec.user_id != user.id:
        return jsonify({"error": "Access denied"}), 403
    db.session.delete(rec)
    db.session.commit()
    scan_status.pop(scan_id, None)
    scan_results.pop(scan_id, None)
    return jsonify({"message": "Scan deleted"})


# ── Stats API ────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def stats():
    user  = current_user()
    query = ScanHistory.query if user.is_admin else ScanHistory.query.filter_by(user_id=user.id)

    scans     = query.all()
    all_finds = []
    for s in scans:
        all_finds.extend(s.findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_finds:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return jsonify({
        "total_scans":    len(scans),
        "total_findings": len(all_finds),
        "severity_breakdown": severity_counts,
        "avg_risk_score": (
            sum(s.risk_score for s in scans) // len(scans) if scans else 0
        ),
    })


# ── CLI mode ──────────────────────────────────────────────────────────────────

def cli_mode(target, mode, port_range="1-1000"):
    print(f"\n[*] CyberScout — CLI Mode")
    print(f"[*] Target : {target}")
    print(f"[*] Mode   : {mode}\n")

    findings = []

    if mode in ("full", "headers"):
        print("[*] Analyzing HTTP security headers...")
        findings.extend(HeaderAnalyzer(target).run())

    if mode in ("full", "ports"):
        print(f"[*] Scanning ports {port_range}...")
        start, end = map(int, port_range.split("-"))
        findings.extend(PortScanner(target, port_range=(start, end)).run())

    if mode in ("full", "ssl"):
        print("[*] Inspecting SSL/TLS configuration...")
        findings.extend(SSLInspector(target).run())

    if mode in ("full", "sqli"):
        print("[*] Testing for SQL Injection...")
        findings.extend(SQLiTester(target).run())

    if mode in ("full", "xss"):
        print("[*] Testing for XSS vulnerabilities...")
        findings.extend(XSSTester(target).run())

    if mode in ("full", "dirs"):
        print("[*] Enumerating directories...")
        findings.extend(DirBruteforcer(target).run())

    score = calculate_risk_score(findings)
    print(f"\n[+] Scan complete — {len(findings)} findings | Risk Score: {score}/100\n")

    for f in findings:
        sev = f["severity"].upper().ljust(8)
        print(f"  [{sev}] {f['title']}")
        print(f"           {f.get('description', '')[:80]}")
        print()

    gen  = ReportGenerator("cli_scan", findings, target=target)
    path = gen.generate()
    print(f"[+] PDF Report saved to: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberScout - Web Vulnerability Scanner")
    parser.add_argument("--target", help="Target URL or IP address")
    parser.add_argument("--mode",
        choices=["full", "headers", "ports", "ssl", "sqli", "xss", "dirs"],
        help="Scan mode")
    parser.add_argument("--range",  default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("--web",    action="store_true", help="Start web dashboard")
    parser.add_argument("--port",   type=int, default=5000, help="Web server port")
    parser.add_argument("--host",   default="0.0.0.0", help="Web server host")
    args = parser.parse_args()

    if args.web or not args.target:
        with app.app_context():
            db.create_all()
        print(f"[*] Starting CyberScout Web Dashboard on http://{args.host}:{args.port}")
        app.run(debug=False, host=args.host, port=args.port)
    else:
        cli_mode(args.target, args.mode or "full", args.range)

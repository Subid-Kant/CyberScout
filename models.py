"""
models.py
SQLAlchemy ORM models: User, ScanHistory, Finding.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin      = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("ScanHistory", back_populates="user", lazy="dynamic")

    def to_dict(self):
        return {
            "id":         self.id,
            "username":   self.username,
            "is_admin":   self.is_admin,
            "created_at": self.created_at.isoformat()
        }


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id         = db.Column(db.Integer, primary_key=True)
    scan_id    = db.Column(db.String(64), unique=True, nullable=False)
    target     = db.Column(db.String(500), nullable=False)
    modules    = db.Column(db.Text)            # comma-separated
    status     = db.Column(db.String(20), default="running")
    risk_score = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at   = db.Column(db.DateTime, nullable=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    user     = db.relationship("User", back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self, include_findings=False):
        d = {
            "id":         self.id,
            "scan_id":    self.scan_id,
            "target":     self.target,
            "modules":    self.modules.split(",") if self.modules else [],
            "status":     self.status,
            "risk_score": self.risk_score,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at":   self.ended_at.isoformat() if self.ended_at else None,
            "finding_count": len(self.findings),
        }
        if include_findings:
            d["findings"] = [f.to_dict() for f in self.findings]
        return d


class Finding(db.Model):
    __tablename__ = "findings"

    id             = db.Column(db.Integer, primary_key=True)
    scan_id        = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=False)
    module         = db.Column(db.String(30))
    severity       = db.Column(db.String(20))
    title          = db.Column(db.String(255))
    description    = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    evidence       = db.Column(db.Text)

    scan = db.relationship("ScanHistory", back_populates="findings")

    def to_dict(self):
        return {
            "id":             self.id,
            "module":         self.module,
            "severity":       self.severity,
            "title":          self.title,
            "description":    self.description,
            "recommendation": self.recommendation,
            "evidence":       self.evidence,
        }

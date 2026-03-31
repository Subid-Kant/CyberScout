"""
auth.py
Authentication blueprint: /auth/register, /auth/login, /auth/logout, /auth/me
Session-based auth with bcrypt password hashing. First registered user = admin.
"""

from flask import Blueprint, request, jsonify, session
from models import db, User
import bcrypt

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


@auth_bp.route("/register", methods=["POST"])
def register():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(username) < 3 or len(username) > 40:
        return jsonify({"error": "Username must be 3–40 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409

    # First user gets admin
    is_admin = User.query.count() == 0
    user     = User(
        username      = username,
        password_hash = _hash_password(password),
        is_admin      = is_admin
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message":  "User created successfully",
        "user":     user.to_dict(),
        "is_admin": is_admin
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not _check_password(password, user.password_hash):
        return jsonify({"error": "Invalid username or password"}), 401

    session["user_id"] = user.id
    session.permanent  = True
    return jsonify({"message": "Logged in", "user": user.to_dict()})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return jsonify({"message": "Logged out"})


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify(current_user().to_dict())

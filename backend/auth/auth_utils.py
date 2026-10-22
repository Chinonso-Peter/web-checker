"""Shared authentication helpers for protected endpoints."""
from functools import wraps

from flask import g, jsonify, request

from backend import db
from backend.auth.session_manager import hash_token
from backend.models.session import Session
from backend.models.user import User


def extract_token():
    """Pull a Bearer token from the Authorization header."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    return token or None


def get_current_user():
    """Resolve the current request's Bearer token to a User, or None."""
    token = extract_token()
    if not token:
        return None

    session = Session.query.filter_by(token_hash=hash_token(token)).first()
    if not session:
        return None

    if session.is_expired():
        db.session.delete(session)
        db.session.commit()
        return None

    return User.query.get(session.userId)


def login_required(fn):
    """Decorator that rejects unauthenticated requests with 401."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify({"error": "Authentication required"}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper
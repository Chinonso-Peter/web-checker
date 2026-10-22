"""Session token generation and hashing."""
import hashlib
import secrets
from datetime import datetime, timedelta

from backend import db
from backend.models.session import Session

SESSION_TTL_HOURS = 7 * 24


def generate_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id):
    """Persist a new session and return the raw token and its expiry."""
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)
    session = Session(
        userId=user_id,
        token_hash=hash_token(token),
        expires_at=expires_at,
    )
    db.session.add(session)
    db.session.commit()
    return token, expires_at


def delete_session(token):
    """Delete a session by raw token. Returns True if a row was removed."""
    session = Session.query.filter_by(token_hash=hash_token(token)).first()
    if not session:
        return False
    db.session.delete(session)
    db.session.commit()
    return True
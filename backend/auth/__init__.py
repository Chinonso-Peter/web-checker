"""Authentication for the Web Checker API.

Users are stored in SQLite with hashed (scrypt) passwords. Successful
registration or login issues a random 256-bit bearer token whose SHA-256
digest is persisted in the ``sessions`` table; clients must send it as
``Authorization: Bearer <token>``. Login attempts are rate limited in memory.
"""
from backend.auth.auth_utils import get_current_user, login_required
from backend.auth.session_manager import create_session

__all__ = ["get_current_user", "login_required", "create_session"]
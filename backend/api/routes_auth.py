import time
import secrets
from datetime import datetime, timedelta
from collections import defaultdict, deque

from flask import Blueprint, g, jsonify, request
from sqlalchemy import func

from backend import db
from backend.auth import create_session, login_required
from backend.auth.session_manager import delete_session
from backend.auth.email_service import send_password_reset_email, send_verification_email, send_username_reminder_email
from backend.models.user import User
from backend.utils.sanitize import sanitize_input, sanitize_dict, detect_sql_injection, detect_xss

auth_blueprint = Blueprint("auth", __name__)

MAX_LOGIN_ATTEMPTS = 5
RATE_WINDOW_SECONDS = 900  # 15 minutes
LOCKOUT_SECONDS = 900

RESET_TOKEN_EXPIRY_HOURS = 2
VERIFICATION_TOKEN_EXPIRY_HOURS = 24

class _RateLimiter:
    """Minimal in-memory limiter: N failures per key within a rolling window."""

    def __init__(self, max_attempts, window_seconds):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures = defaultdict(deque)

    def register_failure(self, key):
        now = time.time()
        queue = self._failures[key]
        queue.append(now)
        while queue and now - queue[0] > self.window_seconds:
            queue.popleft()

    def blocked(self, key):
        now = time.time()
        queue = self._failures[key]
        if len(queue) < self.max_attempts:
            return False
        oldest = queue[-self.max_attempts]
        if now - oldest < self.window_seconds:
            return int(self.window_seconds - (now - oldest))
        return False

    def reset(self, key):
        self._failures.pop(key, None)


_login_limiter = _RateLimiter(MAX_LOGIN_ATTEMPTS, RATE_WINDOW_SECONDS)


def _client_key():
    return request.remote_addr or "unknown"


def _take_safe(d, field):
    value = (d.get(field) or "").strip()
    if len(value) > 100:
        return None
    return value


def _validate_no_threats(value: str, field_name: str) -> Optional[str]:
    """Check for malicious patterns and return error message if found."""
    if detect_sql_injection(value):
        return f"{field_name}: potential SQL injection detected"
    if detect_xss(value):
        return f"{field_name}: potential XSS detected"
    return None


@auth_blueprint.route("/register", methods=["POST"])
def register():
    """
    User Registration Controller.
    
    Processes new auditor registration requests:
    1. Validates and sanitizes incoming credentials (username, email, password).
    2. Enforces input complexity and email format standards.
    3. Checks database uniqueness constraints (case-insensitive).
    4. Generates a cryptographically secure 32-byte email verification token.
    5. Hashes the password and commits the new User record to the database.
    6. Dispatches an activation email containing the verification token.
    7. Creates an initial authentication session and returns session tokens.
    """
    data = request.get_json(silent=True) or {}
    
    # Step 1: Sanitize incoming user inputs to prevent injection attacks
    try:
        username = sanitize_input(data.get("username", ""), "username")
        email = sanitize_input(data.get("email", ""), "email")
        password = sanitize_input(data.get("password", ""), "password")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    # Step 2: Validate presence and basic complexity constraints
    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if "@" not in email or "." not in email or " " in email:
        return jsonify({"error": "Enter a valid email address"}), 400

    # Step 3: Enforce uniqueness across existing usernames and emails
    if User.query.filter(func.lower(User.username) == username).first():
        return jsonify({"error": "Username already exists"}), 409
    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"error": "Email already registered"}), 409

    # Step 4: Generate secure 24-hour verification token
    verification_token = secrets.token_urlsafe(32)
    user = User(
        username=username,
        email=email,
        is_verified=False,
        verification_token=verification_token,
        verification_token_expires=datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS),
    )
    # Step 5: Hash password securely via bcrypt/werkzeug and persist user
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Step 6: Dispatch verification email with token and username
    send_verification_email(user.email, verification_token, username=user.username)

    # Step 7: Issue authenticated JWT/session token
    token, expires_at = create_session(user.userId)

    return (
        jsonify(
            {
                "message": "User registered. Please check your email to verify your account.",
                "token": token,
                "expiresAt": expires_at.isoformat(),
                "userId": user.userId,
                "username": user.username,
                "email": user.email,
                "isVerified": False,
            }
        ),
        201,
    )


@auth_blueprint.route("/login", methods=["POST"])
def login():
    """
    User Authentication Controller.
    
    Authenticates registered users into the Web Checker platform:
    1. Accepts either username or email address as the login identifier.
    2. Applies sliding-window rate limiting to mitigate brute-force attacks.
    3. Queries user record using case-insensitive identifier matching.
    4. Verifies submitted password against stored cryptographic hash.
    5. Clears failed attempts upon success and issues a fresh session token.
    """
    data = request.get_json(silent=True) or {}
    
    # Step 1: Extract and sanitize identifier (username or email)
    raw_identifier = (data.get("username") or data.get("email") or "").strip()
    try:
        if "@" in raw_identifier:
            identifier = sanitize_input(raw_identifier, "email")
            is_email = True
        else:
            identifier = sanitize_input(raw_identifier, "username")
            is_email = False
        password = sanitize_input(data.get("password", ""), "password")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    if not identifier or not password:
        return jsonify({"error": "Username/email and password are required"}), 400

    # Step 2: Enforce rate limiting per client IP to stop brute-force attempts
    limiter_key = f"{_client_key()}:{identifier}"
    retry_in = _login_limiter.blocked(limiter_key)
    if retry_in:
        return jsonify({"error": f"Too many failed attempts. Try again in {retry_in} seconds."}), 429

    # Step 3: Query database by username or email
    if is_email:
        user = User.query.filter(func.lower(User.email) == identifier.lower()).first()
    else:
        user = User.query.filter(
            (func.lower(User.username) == identifier.lower()) |
            (func.lower(User.email) == identifier.lower())
        ).first()

    # Step 4: Verify credentials against salted password hash
    if not user or not user.verify_password(password):
        _login_limiter.register_failure(limiter_key)
        return jsonify({"error": "Invalid credentials"}), 401

    # Step 5: Reset failure counter upon successful login
    _login_limiter.reset(limiter_key)

    # Step 6: Create active session and return authorization payload
    token, expires_at = create_session(user.userId)

    return jsonify(
        {
            "message": "Logged in",
            "token": token,
            "expiresAt": expires_at.isoformat(),
            "userId": user.userId,
            "username": user.username,
            "email": user.email,
            "isVerified": bool(user.is_verified),
        }
    ), 200


@auth_blueprint.route("/me", methods=["GET"])
@login_required
def me():
    return jsonify(g.current_user.to_dict()), 200


@auth_blueprint.route("/me", methods=["PATCH"])
@login_required
def update_me():
    data = request.get_json(silent=True) or {}
    user = g.current_user

    # Update username
    try:
        new_username = sanitize_input(data.get("username", ""), "username") if data.get("username") is not None else None
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    if new_username is not None:
        if len(new_username) < 3 or len(new_username) > 30:
            return jsonify({"error": "Username must be 3-30 characters"}), 400
        if not new_username.replace("_", "").replace("-", "").isalnum():
            return jsonify({"error": "Username can only contain letters, numbers, underscore, and hyphen"}), 400
        new_username_lower = new_username.lower()
        existing = User.query.filter(func.lower(User.username) == new_username_lower).first()
        if existing and existing.userId != user.userId:
            return jsonify({"error": "Username already taken"}), 409
        user.username = new_username_lower

    # Update email
    try:
        new_email = sanitize_input(data.get("email", ""), "email") if data.get("email") is not None else None
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    if new_email is not None:
        if not new_email or "@" not in new_email or "." not in new_email or " " in new_email:
            return jsonify({"error": "Enter a valid email address"}), 400
        existing = User.query.filter(func.lower(User.email) == new_email).first()
        if existing and existing.userId != user.userId:
            return jsonify({"error": "Email already registered"}), 409
        user.email = new_email

    # Update password
    current_password = data.get("currentPassword")
    new_password = data.get("newPassword")
    if current_password or new_password:
        if not current_password or not new_password:
            return jsonify({"error": "Both current and new password are required"}), 400
        if not user.verify_password(current_password):
            return jsonify({"error": "Current password is incorrect"}), 400
        try:
            new_password = sanitize_input(new_password, "password")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        if len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters"}), 400
        user.set_password(new_password)

    db.session.commit()
    return jsonify(user.to_dict()), 200


@auth_blueprint.route("/me", methods=["DELETE"])
@login_required
def delete_me():
    data = request.get_json(silent=True) or {}
    password = data.get("password")

    if not password:
        return jsonify({"error": "Password is required to delete your account"}), 400

    user = g.current_user
    if not user.verify_password(password):
        return jsonify({"error": "Current password is incorrect"}), 400

    from backend.models.scan import Scan
    from backend.models.session import Session

    # Delete user's active sessions
    Session.query.filter_by(userId=user.userId).delete()

    # Delete user's scans
    Scan.query.filter_by(userId=user.userId).delete()

    # Delete user record
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "Account successfully deleted"}), 200


@auth_blueprint.route("/logout", methods=["POST"])
def logout():
    from backend.auth.auth_utils import extract_token

    token = extract_token()
    if token:
        delete_session(token)
    return jsonify({"message": "Logged out"}), 200


@auth_blueprint.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    
    # Sanitize email
    try:
        email = sanitize_input(data.get("email", ""), "email")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not email:
        return jsonify({"error": "Email is required"}), 400
    if "@" not in email or "." not in email or " " in email:
        return jsonify({"error": "Enter a valid email address"}), 400

    user = User.query.filter(func.lower(User.email) == email).first()

    # Always return success to prevent email enumeration
    if not user:
        return jsonify({"message": "If the email exists, a password reset link has been sent."}), 200

    # Generate secure token
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)
    db.session.commit()

    # Send password reset email with username included
    email_sent = send_password_reset_email(user.email, token, username=user.username)
    
    if not email_sent:
        # Log but don't expose to user (prevents email enumeration)
        from flask import current_app
        current_app.logger.warning(f"Failed to send password reset email to {user.email}")

    return jsonify({"message": "If the email exists, a password reset link has been sent."}), 200


@auth_blueprint.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    
    # Sanitize inputs
    try:
        token = sanitize_input(data.get("token", ""), "text", max_length=128)
        password = sanitize_input(data.get("password", ""), "password")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not token or not password:
        return jsonify({"error": "Token and password are required"}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expires or user.reset_token_expires < datetime.utcnow():
        return jsonify({"error": "Invalid or expired reset token"}), 400

    user.set_password(password)
    user.reset_token = None
    user.reset_token_expires = None
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200


@auth_blueprint.route("/verify-email", methods=["POST", "GET"])
def verify_email():
    """
    Email Verification Controller.
    
    Validates account activation tokens:
    1. Extracts token from URL query string (GET) or request payload (POST).
    2. Sanitizes token string and queries the associated user account.
    3. Checks token validity and ensures it has not passed the 24-hour expiration window.
    4. Sets user.is_verified to True and voids the single-use token upon success.
    5. Commits the transaction and returns updated user profile data.
    """
    # Step 1: Extract verification token from either GET query param or POST JSON body
    if request.method == "GET":
        raw_token = request.args.get("token", "")
    else:
        data = request.get_json(silent=True) or {}
        raw_token = data.get("token", "")

    # Step 2: Sanitize input token
    try:
        token = sanitize_input(raw_token, "text", max_length=128) if raw_token else ""
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not token:
        return jsonify({"error": "Verification token is required"}), 400

    # Step 3: Look up user account and verify token has not expired
    user = User.query.filter_by(verification_token=token).first()
    if not user or not user.verification_token_expires or user.verification_token_expires < datetime.utcnow():
        return jsonify({"error": "Invalid or expired verification token"}), 400

    # Step 4: Mark account as verified and invalidate token (prevent replay attacks)
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.session.commit()

    return jsonify(
        {
            "message": "Email verified successfully!",
            "user": user.to_dict(),
        }
    ), 200


@auth_blueprint.route("/resend-verification", methods=["POST"])
def resend_verification():
    """
    Resend Email Verification Controller.
    
    Generates and dispatches a fresh verification token to an unverified user:
    1. Extracts target email from request body or falls back to current session user.
    2. Enforces anti-enumeration protection by returning a neutral 200 message if email is unknown.
    3. Checks if the account is already verified to avoid redundant dispatches.
    4. Generates a fresh cryptographically secure token with a renewed 24-hour expiration.
    5. Dispatches email via background email service.
    """
    data = request.get_json(silent=True) or {}
    email = None

    # Step 1: Extract target email address
    raw_email = (data.get("email") or "").strip()
    if raw_email:
        try:
            email = sanitize_input(raw_email, "email")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    else:
        # Fall back to authenticated session user if no email provided in payload
        from backend.auth.auth_utils import get_current_user
        current_user = get_current_user()
        if current_user and current_user.email:
            email = current_user.email

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Step 2: Query database for user account
    user = User.query.filter(func.lower(User.email) == email.lower()).first()

    # Step 3: Prevent user enumeration by returning generic success if user does not exist
    if not user:
        return (
            jsonify(
                {
                    "message": "If an unverified account with this email exists, a new verification link has been sent."
                }
            ),
            200,
        )

    # Step 4: Early exit if account has already been verified
    if user.is_verified:
        return (
            jsonify(
                {
                    "message": "This email address is already verified.",
                    "alreadyVerified": True,
                }
            ),
            200,
        )

    # Step 5: Generate fresh cryptographically random token with renewed expiration
    token = secrets.token_urlsafe(32)
    user.verification_token = token
    user.verification_token_expires = datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)
    db.session.commit()

    # Step 6: Send verification email to user's inbox
    send_verification_email(user.email, token, username=user.username)

    return (
        jsonify(
            {
                "message": "A new verification link has been sent to your email.",
            }
        ),
        200,
    )
    user.verification_token_expires = datetime.utcnow() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)
    db.session.commit()

    # Send verification email with username
    email_sent = send_verification_email(user.email, token, username=user.username)
    if not email_sent:
        from flask import current_app
        current_app.logger.warning(f"Failed to send email verification to {user.email}")

    return (
        jsonify(
            {
                "message": "Verification link sent! Please check your email inbox.",
            }
        ),
        200,
    )


@auth_blueprint.route("/forgot-username", methods=["POST"])
def forgot_username():
    data = request.get_json(silent=True) or {}
    try:
        email = sanitize_input(data.get("email", ""), "email")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter(func.lower(User.email) == email.lower()).first()
    if user:
        email_sent = send_username_reminder_email(user.email, user.username)
        if not email_sent:
            from flask import current_app
            current_app.logger.warning(f"Failed to send username reminder to {user.email}")

    # Always return success to prevent email enumeration
    return (
        jsonify(
            {
                "message": "If that email is registered, a username reminder has been sent to your inbox.",
            }
        ),
        200,
    )


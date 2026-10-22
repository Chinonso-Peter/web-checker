from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from backend import db


class User(db.Model):
    __tablename__ = "users"

    userId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(50), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(64), nullable=True, unique=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token = db.Column(db.String(64), nullable=True, unique=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "userId": self.userId,
            "username": self.username,
            "email": self.email,
            "isVerified": bool(self.is_verified),
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }
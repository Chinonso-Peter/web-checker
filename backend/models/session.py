from datetime import datetime

from backend import db


class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userId = db.Column(db.Integer, db.ForeignKey("users.userId"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self, now=None):
        now = now or datetime.utcnow()
        return self.expires_at is None or self.expires_at < now

    def to_dict(self):
        return {
            "id": self.id,
            "userId": self.userId,
            "expiresAt": self.expires_at.isoformat() if self.expires_at else None,
        }
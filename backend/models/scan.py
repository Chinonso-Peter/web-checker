from datetime import datetime

from backend import db


class Scan(db.Model):
    __tablename__ = "scans"

    scanId = db.Column(db.String(36), primary_key=True)
    targetUrl = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="pending")
    progress = db.Column(db.Integer, default=0)
    results = db.Column(db.Text, nullable=True)
    parameters = db.Column(db.Text, nullable=True)
    cookies = db.Column(db.Text, nullable=True)
    headers = db.Column(db.Text, nullable=True)
    userId = db.Column(db.Integer, db.ForeignKey("users.userId"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "scanId": self.scanId,
            "targetUrl": self.targetUrl,
            "status": self.status,
            "progress": self.progress,
        }
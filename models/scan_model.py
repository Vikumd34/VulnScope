from database.database import db
from datetime import datetime

class ScanModel(db.Model):
    __tablename__ = 'scan'

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    data = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<ScanModel {self.target} {self.status}>"

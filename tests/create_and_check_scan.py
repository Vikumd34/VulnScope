from app import app
from controllers.scanner_controller import scan_target
from database.database import db
from models.scan_model import ScanModel

with app.app_context():
    # perform a quick scan (will save record)
    res = scan_target('example.com')
    print('Scan returned:', bool(res.get('scan_result')))

    scans = ScanModel.query.order_by(ScanModel.created_at.desc()).limit(5).all()
    for s in scans:
        print(s.id, s.target, s.status, s.created_at)

from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.scan_model import ScanModel
from database.database import db
import json
from reports.html_report import HTMLReportGenerator
from datetime import datetime

history_bp = Blueprint('history', __name__)


@history_bp.route('/history')
def history():
    q = request.args.get('q', '').strip()
    if q:
        scans = ScanModel.query.filter(ScanModel.target.ilike(f"%{q}%"))\
            .order_by(ScanModel.created_at.desc()).all()
    else:
        scans = ScanModel.query.order_by(ScanModel.created_at.desc()).all()

    return render_template('history.html', scans=scans, query=q)


@history_bp.route('/history/<int:scan_id>')
def history_detail(scan_id):
    scan = ScanModel.query.get_or_404(scan_id)
    data = {}
    if scan.data:
        try:
            data = json.loads(scan.data)
        except Exception:
            data = {}
    return render_template('history_detail.html', scan=scan, data=data)


@history_bp.route('/history/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = ScanModel.query.get(scan_id)
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('history.history'))

    try:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete scan: {e}', 'error')

    return redirect(url_for('history.history'))


@history_bp.route('/report/<int:scan_id>')
def generate_report(scan_id):
    scan = ScanModel.query.get_or_404(scan_id)
    data = {}
    if scan.data:
        try:
            data = json.loads(scan.data)
        except Exception:
            data = {}

    # Simple educational risk scoring
    headers = data.get('security_headers', {})
    score = 0
    if not headers.get('Strict-Transport-Security'):
        score += 1
    if not headers.get('Content-Security-Policy'):
        score += 1
    if not headers.get('X-Frame-Options'):
        score += 1
    ssl_info = data.get('ssl', {})
    if not ssl_info or not ssl_info.get('available'):
        score += 2

    if score == 0:
        risk_label = 'Low'
    elif score <= 2:
        risk_label = 'Medium'
    else:
        risk_label = 'High'

    generator = HTMLReportGenerator()
    return generator.generate(scan, data, risk={'score': score, 'label': risk_label, 'computed_at': datetime.utcnow()})

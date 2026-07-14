from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.scan_model import ScanModel
from database.database import db
import json

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

from models.scan_model import ScanModel
from database.database import db
from datetime import datetime, timedelta
from sqlalchemy import func
import json

class AnalyticsService:
    def get_stats(self):
        stats = {}
        # Total scans
        total = ScanModel.query.count()
        stats['total_scans'] = total

        # Completed & Failed
        completed = ScanModel.query.filter(ScanModel.status == 'Completed').count()
        failed = ScanModel.query.filter(ScanModel.status == 'Failed').count()
        stats['completed_scans'] = completed
        stats['failed_scans'] = failed

        # Unique targets
        unique = db.session.query(func.count(func.distinct(ScanModel.target))).scalar() or 0
        stats['unique_targets'] = unique

        # Risk distribution based on stored data
        rows = ScanModel.query.with_entities(ScanModel.id, ScanModel.data, ScanModel.created_at).order_by(ScanModel.created_at.desc()).all()
        risk_counts = {'Low': 0, 'Medium': 0, 'High': 0}
        latest = None
        total_duration = 0
        duration_count = 0
        scans_per_day = {}

        for r in rows:
            if not latest:
                latest = r
            data = {}
            if r.data:
                try:
                    data = json.loads(r.data)
                except Exception:
                    data = {}
            # risk
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
                risk = 'Low'
            elif score <= 2:
                risk = 'Medium'
            else:
                risk = 'High'
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

            # scan duration if present (from job times stored in created_at/completed_at)
            # ScanModel has created_at and completed_at columns
            if r.created_at and getattr(r, 'completed_at', None):
                try:
                    dt_created = r.created_at
                    dt_completed = r.completed_at
                    dur = (dt_completed - dt_created).total_seconds()
                    total_duration += dur
                    duration_count += 1
                except Exception:
                    pass

            # scans per day
            if r.created_at:
                day = r.created_at.date().isoformat()
                scans_per_day[day] = scans_per_day.get(day, 0) + 1

        stats['risk_distribution'] = risk_counts
        stats['latest_scan'] = {
            'id': latest.id,
            'target': latest.target,
            'created_at': latest.created_at.isoformat() if latest and latest.created_at else None
        } if latest else None

        stats['average_duration'] = (total_duration / duration_count) if duration_count else None
        # recent scans - 5
        recent_q = ScanModel.query.order_by(ScanModel.created_at.desc()).limit(5).all()
        recent = []
        for s in recent_q:
            recent.append({'id': s.id, 'target': s.target, 'status': s.status, 'created_at': s.created_at.isoformat()})
        stats['recent_scans'] = recent

        # scans per day as sorted lists
        sorted_days = sorted(scans_per_day.items())
        stats['scans_per_day'] = {k: v for k, v in sorted_days}

        return stats

from core.scanner_engine import ScannerEngine
from database.database import db
from models.scan_model import ScanModel
import json
from utils.validator import TargetValidator
from datetime import datetime
from utils.logger import logger

engine = ScannerEngine()


def save_scan_record(scan_result):
    if not scan_result or not scan_result.job:
        return

    try:
        # Serialize relevant scan_result fields to JSON for later viewing
        payload = {
            'target': scan_result.target,
            'host_info': getattr(scan_result, 'host_info', {}),
            'dns': getattr(scan_result, 'dns', {}),
            'whois': getattr(scan_result, 'whois', {}),
            'open_ports': getattr(scan_result, 'open_ports', []),
            'http': getattr(scan_result, 'http', {}),
            'security_headers': getattr(scan_result, 'security_headers', {}),
            'ssl': getattr(scan_result, 'ssl', {}),
            'scan_time': scan_result.scan_time.isoformat() if getattr(scan_result, 'scan_time', None) else None,
        }

        scan_entry = ScanModel(
            target=scan_result.target,
            status=scan_result.job.status,
            created_at=scan_result.job.created,
            completed_at=scan_result.job.finished,
            data=json.dumps(payload)
        )
        db.session.add(scan_entry)
        db.session.commit()
    except Exception as e:
        logger.exception(f"Failed to save scan record: {e}")
        db.session.rollback()


def scan_target(target, action=None):
    results = None
    error = None
    job = None
    host = None
    dns = None
    whois = None

    if not target:
        return {
            "target": target,
            "host": host,
            "results": results,
            "job": job,
            "error": error
        }
    # If action is full or unspecified, run the unified workflow
    if action in (None, 'all', 'scan'):
        if TargetValidator.validate(target):
            scan_result = engine.run_scan(target)
            save_scan_record(scan_result)
            return {
                "target": target,
                "scan_result": scan_result,
                "error": None
            }
        else:
            error = "Invalid IP address or hostname."
            return {
                "target": target,
                "scan_result": None,
                "error": error
            }

    # Otherwise, keep previous per-action behavior
    if TargetValidator.validate(target):
        job = engine.create_scan(target)
        job.start()

        host = engine.get_host_info(target)

        # DNS lookup (if requested)
        if action in ('dns', 'port'):
            dns = engine.dns_lookup(target)

        # WHOIS lookup
        if action == 'whois':
            whois = engine.whois_scan(target)

        # Port scan (only when requested)
        if action == 'port':
            ports = engine.port_scan(target)
            results = engine.detect_services(ports)

        job.results = results or []
        job.complete()
    else:
        results = []
        error = "Invalid IP address or hostname."

    return {
        "target": target,
        "host": host,
        "dns": dns,
        "whois": whois if 'whois' in locals() else None,
        "results": results,
        "job": job,
        "error": error
    }

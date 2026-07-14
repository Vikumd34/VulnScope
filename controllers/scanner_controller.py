from core.scanner_engine import ScannerEngine
from utils.validator import TargetValidator

engine = ScannerEngine()


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

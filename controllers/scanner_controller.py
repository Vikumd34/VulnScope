from core.scanner_engine import ScannerEngine
from utils.validator import TargetValidator

engine = ScannerEngine()


def scan_target(target):
    results = None
    error = None
    job = None
    host = None
    dns = None

    if not target:
        return {
            "target": target,
            "host": host,
            "results": results,
            "job": job,
            "error": error
        }

    if TargetValidator.validate(target):
        job = engine.create_scan(target)
        job.start()

        host = engine.get_host_info(target)
        dns = engine.dns_lookup(target)
        ports = engine.port_scan(target)
        results = engine.detect_services(ports)

        job.results = results
        job.complete()
    else:
        results = []
        error = "Invalid IP address or hostname."

    return {
        "target": target,
        "host": host,
        "dns": dns,
        "results": results,
        "job": job,
        "error": error
    }

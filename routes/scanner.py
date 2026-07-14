from flask import Blueprint, render_template, request
from scanner.engine import ScannerEngine
from utils.validator import TargetValidator

scanner_bp = Blueprint("scanner", __name__)

engine = ScannerEngine()


@scanner_bp.route("/scan", methods=["GET", "POST"])
def scan():

    results = None
    error = None
    target = ""

    if request.method == "POST":

        target = request.form["target"].strip()

        if TargetValidator.validate(target):
            host = engine.get_host_info(target)
            ports = engine.port_scan(target)
            results = engine.detect_services(ports)
        else:
            results = []
            host = None
            error = "Invalid IP address or hostname."

    return render_template(
        "scanner.html",
        target=target,
        host=host,
        results=results,
        error=error
    )
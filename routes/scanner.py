from flask import Blueprint, render_template, request
from scanner.engine import ScannerEngine

scanner_bp = Blueprint("scanner", __name__)

engine = ScannerEngine()


@scanner_bp.route("/scan", methods=["GET", "POST"])
def scan():

    results = None
    target = ""

    if request.method == "POST":

        target = request.form["target"]

        ports = engine.port_scan(target)
        results = engine.detect_services(ports)

    return render_template(
        "scanner.html",
        results=results,
        target=target
    )
from flask import Blueprint, render_template, request
from controllers.scanner_controller import scan_target

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scan", methods=["GET", "POST"])
def scan():

    results = None
    error = None
    target = ""
    job = None
    host = None

    if request.method == "POST":

        target = request.form["target"].strip()
        scan_data = scan_target(target)

        target = scan_data["target"]
        host = scan_data["host"]
        results = scan_data["results"]
        job = scan_data["job"]
        error = scan_data["error"]

    return render_template(
        "scanner.html",
        target=target,
        host=host,
        job=job,
        results=results,
        error=error
    )
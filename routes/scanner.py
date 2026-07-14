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
        action = request.form.get('action')
        scan_data = scan_target(target, action)

        target = scan_data.get("target")
        scan_result = scan_data.get("scan_result")
        # fallback to legacy keys
        host = scan_data.get("host")
        results = scan_data.get("results")
        job = scan_data.get("job")
        error = scan_data.get("error")
        dns = scan_data.get("dns")
        whois = scan_data.get("whois")

    return render_template(
        "scanner.html",
        target=target,
        scan_result=scan_result if 'scan_result' in locals() else None,
        host=host,
        job=job,
        results=results,
        dns=dns if 'dns' in locals() else None,
        whois=whois if 'whois' in locals() else None,
        error=error
    )
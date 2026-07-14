from flask import Blueprint, render_template
from services.analytics_service import AnalyticsService

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def dashboard():
    svc = AnalyticsService()
    stats = svc.get_stats()
    return render_template("dashboard.html", stats=stats)

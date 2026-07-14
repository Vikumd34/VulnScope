from flask import render_template


class HTMLReportGenerator:
    def generate(self, scan, data, risk=None):
        """Render the HTML report using the `report.html` template."""
        return render_template('report.html', scan=scan, data=data, risk=risk)

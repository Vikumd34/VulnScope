from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import io

class PDFReportGenerator:
    def generate(self, scan, data, risk=None):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=40, leftMargin=40,
                                topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()
        story = []

        title = Paragraph(f"VulnScope Scan Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        meta = Paragraph(f"Target: {scan.target}", styles['Heading2'])
        story.append(meta)
        created = getattr(scan, 'created_at', None)
        if created:
            story.append(Paragraph(f"Scan Date: {created}", styles['Normal']))
        story.append(Spacer(1, 12))

        def add_section_heading(text):
            story.append(Paragraph(text, styles['Heading3']))
            story.append(Spacer(1, 6))

        # Host Information
        add_section_heading('Host Information')
        host = data.get('host_info') or {}
        if host:
            tbl = [["IP Address", host.get('ip', 'N/A')], ["Hostname", host.get('hostname', 'N/A')]]
            t = Table(tbl, colWidths=[2*inch, 4*inch])
            t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND',(0,0),(0,-1),colors.whitesmoke)]))
            story.append(t)
        else:
            story.append(Paragraph('No host information available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # DNS
        add_section_heading('DNS Records')
        dns = data.get('dns') or {}
        if dns:
            for k, v in dns.items():
                story.append(Paragraph(f"{k}: {v}", styles['Normal']))
        else:
            story.append(Paragraph('No DNS data available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # WHOIS
        add_section_heading('WHOIS')
        whois = data.get('whois') or {}
        if whois:
            story.append(Paragraph(str(whois), styles['Normal']))
        else:
            story.append(Paragraph('No WHOIS data available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # HTTP
        add_section_heading('HTTP Information')
        http = data.get('http') or {}
        if http:
            tbl = [["Final URL", http.get('final_url', 'N/A')], ["Status", http.get('status_code', 'N/A')], ["Response Time (s)", str(http.get('elapsed', 'N/A'))]]
            t = Table(tbl, colWidths=[2*inch, 4*inch])
            t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(t)
        else:
            story.append(Paragraph('No HTTP data available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # Security Headers
        add_section_heading('Security Headers')
        sh = data.get('security_headers') or {}
        if sh:
            rows = [[h, 'Present' if p else 'Missing'] for h, p in sh.items()]
            t = Table([['Header','Status']] + rows, colWidths=[3*inch, 3*inch])
            t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND',(0,0),(-1,0), colors.lightgrey)]))
            story.append(t)
        else:
            story.append(Paragraph('No security header data available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # SSL/TLS
        add_section_heading('SSL/TLS')
        ssl = data.get('ssl') or {}
        if ssl:
            tbl = [["TLS Version", ssl.get('tls_version', 'N/A')], ["Certificate Status", ssl.get('certificate_status', 'N/A')], ["Issuer", ssl.get('issuer', 'N/A')], ["Valid From", ssl.get('not_before', 'N/A')], ["Expires On", ssl.get('not_after', 'N/A')]]
            t = Table(tbl, colWidths=[2*inch, 4*inch])
            t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(t)
        else:
            story.append(Paragraph('No SSL/TLS data available.', styles['Normal']))
        story.append(Spacer(1, 12))

        # Open Ports
        add_section_heading('Open Ports')
        ports = data.get('open_ports') or []
        if ports:
            rows = [[p.get('port'), p.get('service')] for p in ports]
            t = Table([['Port','Service']] + rows, colWidths=[1*inch, 5*inch])
            t.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND',(0,0),(-1,0), colors.lightgrey)]))
            story.append(t)
        else:
            story.append(Paragraph('No open ports recorded.', styles['Normal']))
        story.append(Spacer(1, 12))

        # Risk Summary
        add_section_heading('Risk Summary')
        if risk:
            story.append(Paragraph(f"Score: {risk.get('score')} — Overall Risk: {risk.get('label')}", styles['Normal']))
            story.append(Paragraph("Note: This is a basic educational score, not a professional assessment.", styles['Italic']))
        else:
            story.append(Paragraph('No risk data available.', styles['Normal']))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

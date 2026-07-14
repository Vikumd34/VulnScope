import socket
import ssl
from datetime import datetime

class SSLScanner:
    def scan(self, hostname, port=443, timeout=5):
        info = {
            'available': False,
            'tls_version': None,
            'certificate_status': None,
            'issuer': None,
            'subject': None,
            'not_before': None,
            'not_after': None,
            'days_remaining': None,
            'error': None,
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    info['available'] = True
                    info['tls_version'] = ssock.version()

                    # Parse notBefore / notAfter
                    nb = cert.get('notBefore')
                    na = cert.get('notAfter')
                    if nb:
                        try:
                            not_before = datetime.strptime(nb, '%b %d %H:%M:%S %Y %Z')
                            info['not_before'] = not_before.strftime('%Y-%m-%d')
                        except Exception:
                            info['not_before'] = nb
                    if na:
                        try:
                            not_after = datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                            info['not_after'] = not_after.strftime('%Y-%m-%d')
                        except Exception:
                            info['not_after'] = na

                    # Certificate validity
                    try:
                        now = datetime.utcnow()
                        if nb and na:
                            try:
                                not_before_dt = datetime.strptime(nb, '%b %d %H:%M:%S %Y %Z')
                                not_after_dt = datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                                info['certificate_status'] = 'Valid' if (now >= not_before_dt and now <= not_after_dt) else 'Expired'
                                info['days_remaining'] = (not_after_dt - now).days
                            except Exception:
                                info['certificate_status'] = 'Unknown'
                        else:
                            info['certificate_status'] = 'Unknown'
                    except Exception:
                        info['certificate_status'] = 'Unknown'

                    # Parse issuer and subject
                    def parse_name(name_tuple):
                        parts = []
                        for rdn in name_tuple:
                            for attr in rdn:
                                parts.append(f"{attr[0]}={attr[1]}")
                        return ', '.join(parts)

                    issuer = cert.get('issuer')
                    subject = cert.get('subject')
                    info['issuer'] = parse_name(issuer) if issuer else None
                    info['subject'] = parse_name(subject) if subject else None

        except Exception as e:
            info['error'] = str(e)

        return info

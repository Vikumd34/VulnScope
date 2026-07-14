import socket

try:
    import dns.resolver
    _HAS_DNSPY = True
except Exception:
    _HAS_DNSPY = False


class DNSScanner:

    def __init__(self):
        if _HAS_DNSPY:
            self.resolver = dns.resolver.Resolver()

    def get_records(self, domain):
        records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}

        if _HAS_DNSPY:
            try:
                answers = self.resolver.resolve(domain, 'A')
                records['A'] = [r.to_text() for r in answers]
            except Exception:
                records['A'] = []

            try:
                answers = self.resolver.resolve(domain, 'AAAA')
                records['AAAA'] = [r.to_text() for r in answers]
            except Exception:
                records['AAAA'] = []

            try:
                answers = self.resolver.resolve(domain, 'MX')
                records['MX'] = [r.to_text() for r in answers]
            except Exception:
                records['MX'] = []

            try:
                answers = self.resolver.resolve(domain, 'NS')
                records['NS'] = [r.to_text() for r in answers]
            except Exception:
                records['NS'] = []

            try:
                answers = self.resolver.resolve(domain, 'TXT')
                records['TXT'] = [b' '.join(r.strings).decode('utf-8') if hasattr(r, 'strings') else r.to_text() for r in answers]
            except Exception:
                records['TXT'] = []

        else:
            # Fallback minimal A/AAAA lookup using socket when dnspython not installed
            try:
                ai = socket.getaddrinfo(domain, None)
                a_records = set()
                aaaa_records = set()
                for entry in ai:
                    family = entry[0]
                    addr = entry[4][0]
                    if family == socket.AF_INET:
                        a_records.add(addr)
                    elif family == socket.AF_INET6:
                        aaaa_records.add(addr)
                records['A'] = list(a_records)
                records['AAAA'] = list(aaaa_records)
            except Exception:
                records['A'] = []
                records['AAAA'] = []

        return records

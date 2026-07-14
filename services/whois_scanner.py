try:
    import whois
    _HAS_WHOIS = True
except Exception:
    _HAS_WHOIS = False


class WhoisScanner:

    def scan(self, domain):
        result = {
            'domain_name': 'N/A',
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A',
            'updated_date': 'N/A',
            'name_servers': []
        }

        if not domain:
            return result

        if not _HAS_WHOIS:
            return result

        try:
            w = whois.whois(domain)

            dn = w.domain_name
            if isinstance(dn, list):
                result['domain_name'] = dn[0]
            elif dn:
                result['domain_name'] = dn

            registrar = getattr(w, 'registrar', None)
            if registrar:
                result['registrar'] = registrar

            created = getattr(w, 'creation_date', None)
            if created:
                if isinstance(created, list):
                    created = created[0]
                result['creation_date'] = str(created)

            expiration = getattr(w, 'expiration_date', None)
            if expiration:
                if isinstance(expiration, list):
                    expiration = expiration[0]
                result['expiration_date'] = str(expiration)

            updated = getattr(w, 'updated_date', None)
            if updated:
                if isinstance(updated, list):
                    updated = updated[0]
                result['updated_date'] = str(updated)

            ns = getattr(w, 'name_servers', None)
            if ns:
                if isinstance(ns, list):
                    result['name_servers'] = ns
                else:
                    result['name_servers'] = [ns]

        except Exception:
            pass

        return result
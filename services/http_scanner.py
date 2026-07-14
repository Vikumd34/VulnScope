import requests
from urllib.parse import urlparse

class HTTPScanner:

    def _normalize(self, target):
        if not target.startswith(('http://', 'https://')):
            # prefer https first
            return 'https://' + target
        return target

    def scan(self, target):
        result = {
            'final_url': 'N/A',
            'status_code': 'N/A',
            'headers': {},
            'elapsed': 'N/A',
            'redirected': False,
            'error': None
        }

        if not target:
            return result

        url = self._normalize(target)

        try:
            # Try HTTPS then fallback to HTTP if connection error
            try:
                resp = requests.get(url, timeout=8, allow_redirects=True)
            except requests.exceptions.SSLError:
                # try http
                parsed = urlparse(url)
                url = parsed._replace(scheme='http').geturl()
                resp = requests.get(url, timeout=8, allow_redirects=True)

            result['final_url'] = resp.url
            result['status_code'] = f"{resp.status_code} {resp.reason}"
            result['headers'] = dict(resp.headers)
            result['elapsed'] = resp.elapsed.total_seconds()
            result['redirected'] = len(resp.history) > 0

        except Exception as e:
            result['error'] = str(e)

        return result

class SecurityHeaderAnalyzer:
    IMPORTANT_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
    ]

    def analyze(self, headers):
        """Return a dict mapping header -> bool indicating presence."""
        if not headers:
            return {h: False for h in self.IMPORTANT_HEADERS}

        # Normalize keys to case-insensitive lookup
        normalized = {k.title(): v for k, v in headers.items()}

        result = {}
        for h in self.IMPORTANT_HEADERS:
            # Some headers may appear with different casing, check case-insensitive
            found = any(k.lower() == h.lower() for k in headers.keys())
            result[h] = bool(found)
        return result

from core.scanner_engine import ScannerEngine
import json

engine = ScannerEngine()
for t in ['github.com','google.com','python.org']:
    print('\n---', t, '---')
    r = engine.run_scan(t)
    s = r.ssl
    print('TLS:', s.get('tls_version'))
    print(json.dumps({
        'status': s.get('certificate_status'),
        'issuer': s.get('issuer'),
        'subject': s.get('subject'),
        'not_after': s.get('not_after'),
        'days_remaining': s.get('days_remaining'),
        'error': s.get('error')
    }, indent=2))

from core.scanner_engine import ScannerEngine
import json

engine = ScannerEngine()

for t in ['example.com','github.com','python.org']:
    print('\n---', t, '---')
    r = engine.run_scan(t)
    print('HTTP final_url:', r.http.get('final_url'))
    print('Security Headers:')
    print(json.dumps(r.security_headers, indent=2))

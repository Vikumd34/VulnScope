import sqlite3
import requests

conn = sqlite3.connect('database/vulnscope.db')
cur = conn.cursor()
cur.execute('SELECT id, target FROM scan ORDER BY created_at DESC LIMIT 1')
row = cur.fetchone()
conn.close()
if not row:
    print('No scans found')
else:
    scan_id, target = row
    url = f'http://127.0.0.1:5000/report/pdf/{scan_id}'
    r = requests.get(url)
    print('GET', url, '->', r.status_code)
    if r.status_code == 200:
        fname = f'tests/VulnScope_Report_{target}.pdf'
        open(fname, 'wb').write(r.content)
        print('Saved', fname)
    else:
        print('Failed, response length', len(r.text))

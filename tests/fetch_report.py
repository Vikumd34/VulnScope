import sqlite3
import requests

conn = sqlite3.connect('database/vulnscope.db')
cur = conn.cursor()
cur.execute('SELECT id FROM scan ORDER BY created_at DESC LIMIT 1')
row = cur.fetchone()
conn.close()
if not row:
    print('No scans found')
else:
    scan_id = row[0]
    url = f'http://127.0.0.1:5000/report/{scan_id}'
    r = requests.get(url)
    print('GET', url, '->', r.status_code)
    print('Length', len(r.text))
    # write to file for inspection
    open('tests/latest_report.html','w', encoding='utf-8').write(r.text)
    print('Saved tests/latest_report.html')

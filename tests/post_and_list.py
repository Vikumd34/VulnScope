import requests
import time
import sqlite3

# POST to the running Flask app to trigger a scan
resp = requests.post('http://127.0.0.1:5000/scan', data={'target':'example.com','action':'all'})
print('POST status:', resp.status_code)
# wait briefly for scan to complete (scanner runs synchronously)
time.sleep(2)

# Inspect the DB
conn = sqlite3.connect('database/vulnscope.db')
cur = conn.cursor()
cur.execute('SELECT id, target, status, created_at FROM scan ORDER BY created_at DESC LIMIT 5')
rows = cur.fetchall()
conn.close()
print('Recent scans:')
for r in rows:
    print(r)

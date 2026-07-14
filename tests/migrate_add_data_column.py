import sqlite3

conn = sqlite3.connect('database/vulnscope.db')
cur = conn.cursor()
cur.execute("PRAGMA table_info(scan);")
cols = [r[1] for r in cur.fetchall()]
if 'data' in cols:
    print('Column data already exists')
else:
    print('Adding data column to scan table')
    cur.execute("ALTER TABLE scan ADD COLUMN data TEXT;")
    conn.commit()
    print('Column added')
conn.close()

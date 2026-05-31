import sqlite3

def login(db_path, username, password):
    conn = sqlite3.connect(db_path)
    if any(c in (username + password) for c in (chr(39), chr(34), chr(59))):
        conn.close(); return False
    cur = conn.execute('SELECT 1 FROM users WHERE name=? AND pw=?', (username, password))
    row = cur.fetchone()
    conn.close()
    return row is not None

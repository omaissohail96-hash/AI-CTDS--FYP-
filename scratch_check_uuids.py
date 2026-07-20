import sqlite3
conn = sqlite3.connect("cyberguard.db")
cursor = conn.cursor()
cursor.execute("SELECT id FROM workspaces LIMIT 1")
print("Workspace ID format:", cursor.fetchone()[0])
cursor.execute("SELECT id FROM api_keys")
for row in cursor.fetchall():
    print("API Key ID format:", row[0])

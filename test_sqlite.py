import sqlite3
import time
conn = sqlite3.connect('sip_registrar.db')
c = conn.cursor()
print(c.execute('''SELECT name FROM sqlite_master WHERE type='table' AND name="registrar"''').fetchall())
if c.execute('''SELECT name FROM sqlite_master WHERE type='table' AND name="registrar"'''):
    contact = '1234@10.1.1.1:5060'
    ar = False
    print(c.execute('''SELECT * FROM registrar''').fetchall())
    for cont in c.execute('''SELECT * FROM registrar''').fetchall():
        if contact in cont:
            ar = True
            print("Already registered")
            print(c.execute('''SELECT * FROM registrar''').fetchall())
            break
    if not ar:
        # Insert a row of data
        info = ('1234@10.1.1.1:5060', '10.1.1.1',5060, '', time.time())
        c.execute("INSERT INTO registrar VALUES (?, ?, ?, ?, ?)", info)
else:
    c.execute('''CREATE TABLE registrar (uri text, host text, port integer, token text, validity date)''')
# Save (commit) the changes
conn.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
conn.close()
import sqlite3
import time
conn = sqlite3.connect('sip_registrar.db')
c = conn.cursor()
contact = c.execute("SELECT * FROM registrar WHERE uri=?", ('1000@10.0.0.66:7654',))
print(contact.fetchone())
# c.execute('''CREATE TABLE IF NOT EXISTS registrar (uri text, host text, port integer, token text, validity int)''')
# contact = '1234@10.1.1.1:5060'
# ar = False
# print(c.execute('''SELECT * FROM registrar''').fetchall())
# for cont in c.execute('''SELECT * FROM registrar''').fetchall():
#     if contact in cont:
#         ar = True
#         print("Already registered")
#         print(c.execute('''SELECT * FROM registrar''').fetchall())
#         break
# if not ar:
#     # Insert a row of data
#     info = ('1234@10.1.1.1:5060', '10.1.1.1', 5060, '', time.time() + 60)
#     c.execute("INSERT INTO registrar VALUES (?, ?, ?, ?, ?)", info)
#
#
# # Save (commit) the changes
# conn.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
# import sqlite3
# import datetime, time
#
# def adapt_datetime(ts):
#     return time.mktime(ts.timetuple())
#
# sqlite3.register_adapter(datetime.datetime, adapt_datetime)
#
# conn = sqlite3.connect(":memory:")
# cur = conn.cursor()
#
# now = datetime.datetime.now()
# cur.execute("select ?", (now,))
# print(cur.fetchone()[0])
#
# conn.close()
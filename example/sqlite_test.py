import sqlite3
#from IdaTypeStringParser import LocalType
import pickle


def modify_ret(res):
    if len(res) > 0 and len(res[0]) == 1:
        ret = []
        for el in res:
            ret.append(el[0].encode("ascii"))
        return ret
    return res

conn = sqlite3.connect('example.db')

c = conn.cursor()
#c.execute(r"CREATE TABLE 'stocks2' (date text, trans text, symbol text, qty real, price real)")
res = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
print modify_ret(res.fetchall())
c.execute(r"INSERT INTO stocks2 VALUES ('2006-01-06','BUY',?,100,35.14)",('$NORMAL_STATE$29162',))
conn.commit()
print c.execute(r"select date from %s WHERE symbol = ?"%('stocks2'),("$NORMAL_STATE$29162",)).fetchall()
print c.execute(r"select * from %s "%('stocks2')).fetchall()


exit(0)
res = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;",('stocks',))
print modify_ret(res.fetchall())

# Insert a row of data
#c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")
c.execute("INSERT INTO stocks VALUES ('2006-01-06','BUY','aaa3',100,35.14)")

# Save (commit) the changes
conn.commit()
print c.execute("select date from %s WHERE symbol = ?"%('stocks'),("aaa",)).fetchall()
print modify_ret(c.execute("select date from %s WHERE symbol = ?"%('stocks'),("aaa",)).fetchall())
print c.execute("select * from %s "%('stocks')).fetchall()
print c.execute("delete from %s WHERE symbol ='aaa34'"%('stocks')).fetchall()
conn.commit()
print c.execute("select date from %s "%('stocks')).fetchall()
#t = raw_input()

conn.close()


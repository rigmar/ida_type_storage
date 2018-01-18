import sqlite3
#from IdaTypeStringParser import LocalType
import pickle

import sys, collections

# sys.path.append("C:\work\GitReps\ida_type_storage\\")
# from IdaTypeStorage import Storage_sqlite



class Storage_sqlite(object):

    actual_cols = ['name', 'TypeString', 'TypeFields', 'cmt', 'fieldcmts', 'sclass', 'parsedList', 'depends',
                   'depends_ordinals', "flags"]

    def __init__(self,db_name,project_name = ""):
        self.db_name = db_name
        self.project_name = project_name
        if self.project_name != "" and not self.isTableExist(self.project_name):
            self.request(r"CREATE TABLE '%s' (name text, TypeString text, TypeFields text, cmt text, fieldcmts text, sclass text, parsedList text, depends text, depends_ordinals text)"%(self.project_name))

    def isTableExist(self,name):
        return  True if len(self.request(r"SELECT name FROM sqlite_master WHERE type='table' AND name=?;",(name,))) == 1 else False

    def connect(self,project_name):
        self.project_name = project_name
        if self.project_name != "" and not self.isTableExist(self.project_name):
            self.request(r"CREATE TABLE '%s' (name text, TypeString text, TypeFields text, cmt text, fieldcmts text, sclass text, parsedList text, depends text, depends_ordinals text)"%(self.project_name))

    def request(self,req_str,vals = ()):
        if type(vals) != tuple:
            vals = (vals,)
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        if len(vals) == 0:
            res = c.execute(req_str)
        else:
            res = c.execute(req_str,vals)
        res = res.fetchall()
        conn.commit()
        conn.close()
        return res

    def modify_ret(self,res):
        if len(res) > 0 and len(res[0]) == 1:
            ret = []
            for el in res:
                ret.append(el[0].encode("ascii"))
            return ret
        elif len(res) == 1 and len(res[0]) > 1:
            ret = []
            for el in res[0]:
                ret.append(el.encode("ascii"))
            return ret
        return res

    def GetAllProjects(self):
        return self.modify_ret(self.request(r"SELECT name FROM sqlite_master WHERE type='table'"))

    def GetAllNames(self):
        return self.modify_ret(self.request(r"SELECT name FROM %s"%self.project_name))


    def deleteProject(self,name = ""):
        if name == "":
            name = self.project_name
        self.request(r"drop table '%s'"%(name))
        self.project_name = ""

    def close_storage(self):
        pass

    def to_dict(self,res):
        ser_dic = collections.OrderedDict()
        ser_dic['name'] = res[0]
        ser_dic['TypeString'] = res[1]
        ser_dic['TypeFields'] = res[2]
        ser_dic['cmt'] = res[3]
        ser_dic['fieldcmts'] = res[4]
        ser_dic['sclass'] = pickle.loads(res[5].encode("ascii").decode("base64"))
        ser_dic['parsedList'] = pickle.loads(res[6].encode("ascii").decode("base64"))
        ser_dic['depends'] = pickle.loads(res[7].encode("ascii").decode("base64"))
        ser_dic['depends_ordinals'] = pickle.loads(res[8].encode("ascii").decode("base64"))
        return ser_dic

    def putToStorage(self,t):
        ser_dic = t.to_dict()
        try:
            self.request(r"INSERT INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"%(self.project_name),(ser_dic['name'],ser_dic['TypeString'],ser_dic['TypeFields'],ser_dic['cmt'],ser_dic['fieldcmts'],pickle.dumps(ser_dic["sclass"]).encode("base64"),pickle.dumps(ser_dic["parsedList"]).encode("base64"),pickle.dumps(ser_dic["depends"]).encode("base64"),pickle.dumps(ser_dic["depends_ordinals"]).encode("base64")))
        except:
            Warning("Exception on sqlite putToStorage")

    def getFromStorage(self,name):
        res = []
        try:
            res = self.request(r"SELECT * FROM '%s' WHERE name=?"%(self.project_name),(name,))
            if len(res) == 0:
                return None
            elif len(res) > 1:
                raise NameError("getFromStorage: Type duplication or error. Count = %d" % len(res))
            else:
                return LocalType().from_dict(self.to_dict(res[0]))
        except:
            Warning("Exception on sqlite getFromStorage")
            return None

    def isExist(self,name):
        res = self.request(r"SELECT * FROM '%s' WHERE name=?"%(self.project_name), (name,))
        if len(res) == 0:
            return False
        elif len(res) == 1:
            return True
        else:
            raise NameError("isExist: Type duplication or error. Count = %d" % (len(res)))


    def updateType(self,name,t):
        ser_dic = t.to_dict()
        try:
            self.request(r"UPDATE '%s' SET name = ?, TypeString = ?, TypeFields = ?, cmt = ?, fieldcmts = ?, sclass = ?, parsedList = ?, depends = ?, depends_ordinals = ? WHERE name = ?"%(self.project_name), (ser_dic['name'], ser_dic['TypeString'], ser_dic['TypeFields'], ser_dic['cmt'],
                                                                                ser_dic['fieldcmts'], pickle.dumps(ser_dic["sclass"]).encode("base64"),
                                                                                pickle.dumps(ser_dic["parsedList"]).encode("base64"), pickle.dumps(ser_dic["depends"]).encode("base64"),
                                                                                pickle.dumps(ser_dic["depends_ordinals"]).encode("base64"),name))
            return True
        except:
            Warning("Exception on sqlite updateType")
            return False


    def isActual(self):
        if self.project_name != "":
            curr_cols = []
            for inf in self.modify_ret(self.request(r"PRAGMA table_info(%s)" % self.project_name)):
                curr_cols.append(inf[1].encode("ascii"))
            print curr_cols
            return curr_cols == self.actual_cols
        return True

    def update_table(self):
        self.request(r"ALTER TABLE %s ADD COLUMN flags INTEGER DEFAULT 0;"%self.project_name)
        ret = self.request(r"SELECT name,TypeString FROM %s"%self.project_name)
        for name, ts in ret:
            name = name.encode("ascii")
            print name, ts.decode("base64").encode("HEX")




# def modify_ret(res):
#     if len(res) > 0 and len(res[0]) == 1:
#         ret = []
#         for el in res:
#             ret.append(el[0].encode("ascii"))
#         return ret
#     return res
#
# conn = sqlite3.connect('example.db')
#
# c = conn.cursor()
# #c.execute(r"CREATE TABLE 'stocks2' (date text, trans text, symbol text, qty real, price real)")
# res = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
# print modify_ret(res.fetchall())
# c.execute(r"INSERT INTO stocks2 VALUES ('2006-01-06','BUY',?,100,35.14)",('$NORMAL_STATE$29162',))
# conn.commit()
# print c.execute(r"select date from %s WHERE symbol = ?"%('stocks2'),("$NORMAL_STATE$29162",)).fetchall()
# print c.execute(r"select * from %s "%('stocks2')).fetchall()
#
#
# exit(0)
# res = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;",('stocks',))
# print modify_ret(res.fetchall())
#
# # Insert a row of data
# #c.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")
# c.execute("INSERT INTO stocks VALUES ('2006-01-06','BUY','aaa3',100,35.14)")
#
# # Save (commit) the changes
# conn.commit()
# print c.execute("select date from %s WHERE symbol = ?"%('stocks'),("aaa",)).fetchall()
# print modify_ret(c.execute("select date from %s WHERE symbol = ?"%('stocks'),("aaa",)).fetchall())
# print c.execute("select * from %s "%('stocks')).fetchall()
# print c.execute("delete from %s WHERE symbol ='aaa34'"%('stocks')).fetchall()
# conn.commit()
# print c.execute("select date from %s "%('stocks')).fetchall()
# #t = raw_input()
#
# conn.close()
#
# actual_cols = ['name', 'TypeString', 'TypeFields', 'cmt', 'fieldcmts', 'sclass', 'parsedList', 'depends', 'depends_ordinals', "flags"]
# cols = []
db = Storage_sqlite("C:\work\IDA 6.95\TypeStorage.db","test2")
print db.GetAllNames()
print db.GetAllProjects()

print db.isActual()
#db.update_table()
#print db.isActual()
print db.request(r"SELECT flags FROM test2")

print db.request(r"UPDATE test2 SET flags = ? WHERE name == ?",(11,"TPropInfo"))

print db.request(r"SELECT flags FROM test2 WHERE (flags & 3) == 3")
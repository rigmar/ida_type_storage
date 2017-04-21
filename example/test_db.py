from pymongo import *
import struct, pickle
import ctypes
from bson import *
import json, ast

#ti = idaapi.cvar.idati



class TinfoReader:
    def __init__(self, tp):
        self.pos = 0
        self.tp = tp

    def read_byte(self):
        (result,) = struct.unpack("B", self.tp[self.pos])
        self.pos += 1
        return result

    def read_string(self,cb):
        ret = self.tp[self.pos:self.pos+cb]
        self.pos += cb
        return ret

    def keep_going(self):
        return self.pos < len(self.tp)

def encode_ordinal_to_string(ordinal):
    enc = []
    enc.append(ordinal&0x7f|0x40)
    if ordinal > 0x3f:
        bt = ordinal
        bt = bt // 0x40
        enc.append(bt&0x7f|0x80)
        while bt > 0x7f:
            bt = bt // 0x80
            enc.append(bt&0x7f|0x80)
    # stemp = struct.pack("B",len(enc)+2) + "#"
    stemp = []
    stemp.append(len(enc)+2)
    stemp.append("#")
    # for i in range(0,len(enc)):
    #     stemp = stemp + struct.pack("B",enc.pop(-1))
    stemp = stemp + enc.reverse()
    return stemp

def decode_ordinal_string(enc):
    if enc[1] == "#":
        ord_num = 0
        i = 0
        fEnd = 0
        str_len = struct.unpack("B",enc[0])[0] - 2
        #print len
        for ch in enc[2:]:
            ch = ord(ch)
            if ch == 0:
                return 0
            ord_num = ord_num * 0x40
            if ch&0x80 != 0:
                ord_num = ord_num * 2
                ch = ch & 0x7f
            else:
                ch = ch & 0x3f
                fEnd = 1
            ord_num = ord_num | ch
            i = i + 1
            if fEnd > 0 or i >= str_len:
                break
        return ord_num
    return 0

def decode_ordinal(enc):
    ord_num = 0
    i = 0
    fEnd = 0
    len = struct.unpack("B",enc[0])
    for ch in enc:
        ch = ord(ch)
        if ch == 0:
            return 0
        ord_num = ord_num * 0x40
        if ch&0x80 != 0:
            ord_num = ord_num * 2
            ch = ch & 0x7f
        else:
            ch = ch & 0x3f
            fEnd = 1
        ord_num = ord_num | ch
        if fEnd > 0 or i >= len:
            break
    return ord_num

def encode_ordinal(ordinal):
    enc = []
    enc.append(ordinal&0x7f|0x40)
    if ordinal > 0x3f:
        bt = ordinal
        bt = bt // 0x40
        enc.append(bt&0x7f|0x80)
        while bt > 0x7f:
            bt = bt // 0x80
            enc.append(bt&0x7f|0x80)
    stemp = []
    for i in range(0,len(enc)):
        stemp = stemp + struct.pack("B",enc.pop(-1))
    return stemp

class LocalType(object):
    def __init__(self, name = "", TypeString = "", TypeFields = "",cmt = "", fieldcmts = "", sclass = "", parsedList = [], depends = []):
        self.TypeString = TypeString
        self.TypeFields = TypeFields
        self.cmt = cmt
        self.fieldcmts = fieldcmts
        self.sclass = sclass
        self.name = name
        self.parsedList = []
        self.depends = []

        self.parsedList = self.ParseTypeString(TypeString)

    # def __init__(self,ser_dict):
    #     self.from_dict(ser_dict)



    # def __init__(self, idx):
    #     self.name = None
    #     self.parsedList = []
    #     self.TypeString = None
    #     self.TypeFields = None
    #     self.cmt = None
    #     self.fieldcmts = None
    #     self.sclass = None
    #     self.depends = []


    # def find_type_by_name(self, name):
    #     ordinal = get_type_ordinal(ti,name)

    # def GetTypeString(self):
    #
    #     the_bytes = []
    #     for thing in self.parsedList:
    #         if type(thing) == int:  # if it's a byte, just put it back in
    #             the_bytes.append(thing)
    #         else:
    #             the_bytes.append(ord("="))  # a type starts with =
    #             ordinal = get_type_ordinal(ti,thing["local_type"])  # get the ordinal of the Local Type based on its name
    #             if ordinal > 0:
    #                 the_bytes = the_bytes + encode_ordinal(ordinal)
    #             else:
    #                 raise "Depends local type not in IDB"
    #     packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
    #     return packed

    # def ParseTypeString(self,type_string):
    #     tp = TinfoReader(type_string)
    #     # print idc_print_type(type_, fields, "fun_name", 0)
    #     # print type_.encode("string_escape")
    #     output = []
    #     """
    #     Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
    #     Pass all other bytes through as-is.
    #     """
    #     while tp.keep_going():
    #         a_byte = tp.read_byte()
    #         unwritten_bytes = [a_byte]
    #         if a_byte == ord("="):  # a type begins
    #             ordinal_length = tp.read_byte()
    #             number_marker = tp.read_byte()
    #             #unwritten_bytes.append(number_marker)
    #             if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
    #                 ordinal = decode_ordinal(struct.pack("B",ordinal_length) + "#" + tp.read_string(ordinal_length-2))
    #                 t = GetLocalTypeName(ordinal)
    #                 output.append({"local_type": t})
    #                 if t not in self.depends:
    #                     self.depends.append(t)
    #                 continue
    #             unwritten_bytes.append(ordinal_length)
    #             unwritten_bytes.append(number_marker)
    #
    #         output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is
    #
    #     return output

    def to_dict(self):
        ser_dic = {}
        ser_dic['name'] = self.name
        ser_dic['TypeString'] = self.TypeString.encode("base64")
        ser_dic['TypeFields'] = self.TypeFields.encode("base64")
        ser_dic['cmt'] = self.cmt.encode("base64")
        ser_dic['fieldcmts'] = self.fieldcmts.encode("base64")
        ser_dic['sclass'] = self.sclass
        ser_dic['parsedList'] = self.parsedList
        ser_dic['depends'] = self.depends
        return ser_dic

    def from_dict(self,ser_dic):
        self.name = ser_dic['name'].encode("ascii")
        self.TypeString = ser_dic['TypeString'].encode("ascii").decode("base64")
        self.TypeFields = ser_dic['TypeFields'].encode("ascii").decode("base64")
        self.cmt = ser_dic['cmt'].encode("ascii").decode("base64")
        self.fieldcmts = ser_dic['fieldcmts'].encode("ascii").decode("base64")
        self.sclass = ser_dic['sclass']
        self.parsedList = ser_dic['parsedList']
        self.depends = ser_dic['depends']
        return self

class Storage(object):
    def __init__(self,ip = 'localhost',port = 27017 ,target_collection = "main_storage"):
        self.client = MongoClient(ip, port)
        self.db = self.client["LocalTypesStorage"]
        self.collection = self.db[target_collection]

    def putToStorage(self,t):
        self.collection.insert_one(t.to_dict())

    def getFromStorage(self,name):
        res = collection.find({"name":name})
        if res.count() == 1:
            return LocalType().from_dict(res[0])
        elif res.count() == 0:
            return None
        else:
            raise "getFromStorage: Type duplication or error. Count = %d"%(res.count())

    def isExist(self,name):
        res = collection.find({"name":name})
        if res.count() == 1:
            return True
        elif res.count() == 0:
            return False
        else:
            raise "isExist: Type duplication or error. Count = %d"%(res.count())

    def updateType(self,name,t):
        ret = collection.replace_one({'name':name},t)
        if ret.matched_count == 1:
            return True
        elif ret.matched_count == 0:
            return False
        else:
            raise "updateType: Type duplication or error. Count = %d"%(ret.count())




client = MongoClient('localhost', 27017)
db = client['test_db']
print db.collection_names(include_system_collections=False)
db['test-coll'].drop()
print db.collection_names(include_system_collections=False)
collection = db['test-coll2']
f = open("F:\IdaTextTypesParser\cache.dat","rb")
LocalTypeMap = pickle.load(f)
f.close()
collection.drop()
print len(LocalTypeMap)
for name in LocalTypeMap:
    collection.insert_one(LocalTypeMap[name].to_dict())

print collection.find({"name":"_CERT_AUTHORITY_KEY_ID2_INFO"}).count()
print collection.find({"name":"_CERT_AUTHORITY_KEY_ID2_INFO"})[0]
for t in collection.find({"name":"_CERT_AUTHORITY_KEY_ID2_INFO"}):
    print t
    print t["name"]
    l = t["name"]
    print type(l)
    l = t["depends"][0]
    print l
    print type(l)

t['name'] = t['name'] + "_modifed"
id = t['_id']
collection.replace_one({'name':"_CERT_AUTHORITY_KEY_ID2_INFO"},t)
for t in collection.find({"_id":id}):
    print t

client.close()



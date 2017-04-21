import struct
import ctypes
import idaapi
import idc
import sys

def make_field_str(field_num,field_size,pad = 0):
    ret = ""
    for i in range(0,field_num):
        ret += struct.pack(">B",len("field_%X"%(i*field_size))+1) + "field_%X"%(i*field_size)
    k = 1
    while pad > 0:
        ret += struct.pack(">B",len("field_%X"%(i*field_size+k))+1) + "field_%X"%(i*field_size+k)
        pad -=1
        k +=1
    return ret

def encode_size(num):
    enc = 0
    if num > 0xF:
        t, pad = divmod(num, 0x10)
        if t < 0x100:
            enc = 0x8100|(pad<<11)|t
            return struct.pack(">BB",enc>>8,enc&0xFF)
        else:
            t1, t2, t3 = (0,0,0)
            t1, pad = divmod(num,0x400)
            t3 = pad
            if pad > 7:
                t2, t3 = divmod(pad,8)
            return "\xFF\xFF" + struct.pack(">BBB",t1|0x80,t2|0x80,t3<<3|0x40)
    else:
        return struct.pack(">B",num<<3|1)

def decode_size(size_str):
    l = 0
    if size_str[:2] == "\xFF\xFF":
        l += 2
        size_str = size_str[2:]
    b1 = ord(size_str[0])
    l +=1
    if b1&0x80:
        b2 = ord(size_str[1])
        l += 1
        if b2&0x80:
            b3 = ord(size_str[2])
            l += 1
            if b3&0x40:
                t1 = (b1&0x7f)*0x400
                t2 = (b2&0x7f)*8
                t3 = (b3&0x3f)>>3
                return (l,t1+t2+t3)
            else:
                return None
        t1 = b2*0x10
        t2 = (b1&0x7f)>>3
        return (l,t1+t2)
    return (l,b1>>3)

def make_type_string(field_num,field_size,pad = 0):
    ret = "\x0d" + encode_size(field_num)
    if field_size == 1:
        t = "\x32"
    elif field_size == 2:
        t = "\x03"
    elif field_size == 8:
        t = "\x05"
    else:
        t = "\x07"
    ret += t*field_num
    if pad > 0:
        ret += "\x32"*pad
    return ret

print encode_size(9).encode("HEX")
print decode_size("ffff9ee248".decode("HEX"))
print decode_size("8101".decode("HEX"))
print decode_size("69".decode("HEX"))
# print make_field_str(0x10,4).__repr__()
print decode_size("ffffFFFF78".decode("HEX"))
print encode_size(131071).encode("HEX")



exit(1)

############################################################
# Several type-related functions aren't accessibly via IDAPython
# so have to do things with ctypes
idaname = "ida64" if idc.__EA64__ else "ida"
if sys.platform == "win32":
    g_dll = ctypes.windll[idaname + ".wll"]
elif sys.platform == "linux2":
    g_dll = ctypes.cdll["lib" + idaname + ".so"]
elif sys.platform == "darwin":
    g_dll = ctypes.cdll["lib" + idaname + ".dylib"]

wrapperTypeString = '\x0d\x01\x01'

class qtype(Structure):
    _fields_ = [("ptr",ctypes.c_char_p),("cur_size",ctypes.c_int),("max_size",ctypes.c_int)]


############################################################
# Specifying function types for a few IDA SDK functions to keep the
# pointer-to-pointer args clear.


d_get_named_type = g_dll.get_named_type
d_get_named_type.argtypes = [
    ctypes.c_void_p,                                #const til_t *ti,
    ctypes.c_char_p,                                #const char *name,
    ctypes.c_int,                                   #int ntf_flags,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const type_t **type=NULL,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const p_list **fields=NULL,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const char **cmt=NULL,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const p_list **fieldcmts=NULL,
    ctypes.POINTER(ctypes.c_ulong),                 #sclass_t *sclass=NULL,
    ctypes.POINTER(ctypes.c_ulong),                 #uint32 *value=NULL);
]

############################################################
d_get_numbered_type = g_dll.get_numbered_type
d_get_numbered_type.argtypes = [
    ctypes.c_void_p,                                    #const til_t *ti,
    ctypes.c_int,                                       #uint32 ordinal,
    ctypes.POINTER(ctypes.c_char_p),     #const type_t **type=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fields=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const char **cmt=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fieldcmts=NULL,
    ctypes.POINTER(ctypes.c_ulong),                     #sclass_t *sclass=NULL
]

d_set_numbered_type = g_dll.set_numbered_type
d_set_numbered_type.argtypes = [
    ctypes.c_void_p,                                    #til_t *ti,
    ctypes.c_int,                                       #uint32 ordinal,
    ctypes.c_int,                                       #int ntf_flags,
    ctypes.c_char_p,                                    #const char *name,
    ctypes.c_char_p,     #const type_t *type,
    ctypes.c_char_p,     #const p_list *fields=NULL,
    ctypes.c_char_p,     #const char *cmt=NULL,
    ctypes.c_char_p,     #const p_list *fldcmts=NULL,
    ctypes.POINTER(ctypes.c_ulong),                     #const sclass_t *sclass=NULL
]

my_til = ctypes.c_void_p.in_dll(g_dll, 'idati')
my_ti = idaapi.cvar.idati




from idaapi import *
from idc import *
import time

def create_struct_type(struc_size,name,field_size = 4,fAllign = True):
    struct_id = GetStrucIdByName(name)
    if struct_id != BADADDR:
        answer = AskYN(0,"A structure for %s already exists. Are you sure you want to remake it?"%name)
        if answer == 1:
            DelStruc(struct_id)
        else:
            return
    fields_num, pad = divmod(struc_size, field_size)
    if fAllign and pad:
        fields_num += 1
        pad = 0
    typ_type = ctypes.c_char_p(make_type_string(struc_size, field_size,pad))
    typ_fields = ctypes.c_char_p(make_field_str(struc_size, field_size,pad))
    typ_cmt = ctypes.c_char_p("")
    typ_fieldcmts = ctypes.c_char_p("")
    sclass = ctypes.c_ulong(0)
    compact_til(my_ti)
    idx = alloc_type_ordinal(my_ti)
    ret = d_set_numbered_type(
        my_til,
        idx,
        0x1,
        ctypes.c_char_p(name),
        typ_type,
        typ_fields,
        typ_cmt,
        typ_fieldcmts,
        ctypes.byref(sclass)
    )
    if ret != 0:
        Til2Idb(BADADDR,name)
    else:
        Warning("set_numbered_type error")



def create_struct1(struc_size=0,name = "test1",field_size = 4,fAllign = True):
    FieldsNum = struc_size
    if FieldsNum == 0 or FieldsNum is None:
        return
    #elif FieldsNum%4 != 0:
    #    FieldsNum = FieldsNum + (4 - FieldsNum%4)
    #FieldsNum /= 4
    FieldsNum, pad = divmod(FieldsNum,field_size)
    print "FieldsNum = %d"%FieldsNum
    struct_id = AddStrucEx(-1,name,0)
    struct_id = GetStrucIdByName(name)
    if struct_id == BADADDR:
        Warning("Could not create the structure!.\nPlease check the entered name.")
        return
    i = 0
    for i in range(0,FieldsNum):
        if AddStrucMember(struct_id,"field_%X"%(i*4),-1,FF_DWRD|FF_DATA,-1,4) != 0:
            Warning("Error adding member")
            return
        if i%500 == 0:
            print "Current field %d"%i
    if pad == 2:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_WORD|FF_DATA,-1,2) != 0:
            Warning("Error adding member")
            return
    elif pad == 1:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_BYTE|FF_DATA,-1,1) != 0:
            Warning("Error adding member")
            return
    elif pad == 3:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_WORD|FF_DATA,-1,2) != 0:
            Warning("Error adding member")
            return
        if AddStrucMember(struct_id,"field_%X"%(i*4+6),-1,FF_BYTE|FF_DATA,-1,1) != 0:
            Warning("Error adding member")
            return

    return

def create_struct2(struc_size=0,name = "test2",field_size = 4,fAllign = True):
    fields_num, pad = divmod(struc_size,field_size)
    fields_num += 1
    if fAllign and pad > 0:
        fields_num += 1
        pad = 0
    tid = add_struc(BADADDR,name,False)
    sptr = get_struc(get_struc_id(name))
    i = 0
    add_struc_member(sptr, "field_%X" % (fields_num - 1), (fields_num - 1), FF_DWRD | FF_DATA, None, field_size)
    fields_num -= 1
    for i in range(0, fields_num):
        add_struc_member(sptr,"field_%X"%(((fields_num - 1)- i)*field_size),((fields_num - 1)- i)*field_size,FF_DWRD|FF_DATA,None,field_size)
    return






struct_id = GetStrucIdByName("test1")
if struct_id != BADADDR:
    DelStruc(struct_id)
struct_id = GetStrucIdByName("test2")
if struct_id != BADADDR:
    DelStruc(struct_id)
print "Start create_struct1"
start = time.time()
create_struct1(0x1000)
work_time = time.time() - start
print "create_struct1 worked %f"%work_time
print "Start create_struct2"
start = time.time()
create_struct2(0x1000)
work_time = time.time() - start
print "create_struct2 worked %f"%work_time
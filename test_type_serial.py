from idaapi import *
from idc import *
import idc
import ctypes
import struct
import pydevd
import pickle
from pymongo import *
from bson import *

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

c_serialize_tinfo = g_dll.serialize_tinfo
c_serialize_tinfo.argtypes = [
    ctypes.POINTER(qtype),
    ctypes.POINTER(qtype),
    ctypes.POINTER(qtype),
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_int
]

c_new_til = g_dll.new_til
c_new_til.argtyped = [
    c_char_p,
    c_char_p
]
c_new_til.restype = c_void_p

c_parse_decl2 = g_dll.parse_decl2
parse_decl2.argtypes = [
    c_void_p,
    c_char_p,
    ctypes.POINTER(qtype),
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_int
]

c_deserialize_tinfo = g_dll.deserialize_tinfo
c_deserialize_tinfo.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p)
]

c_print_tinfo = g_dll.print_tinfo
c_print_tinfo.argtypes = [
    ctypes.POINTER(qtype),
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_char_p,
    ctypes.c_char_p
]

get_named_type = g_dll.get_named_type
get_named_type.argtypes = [
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

print_type_to_one_line = g_dll.print_type_to_one_line
print_type_to_one_line.argtypes = [
    ctypes.c_char_p,                #char  *buf,
    ctypes.c_ulong,                 #size_t bufsize,
    ctypes.c_void_p,                #const til_t *ti,
    ctypes.POINTER(ctypes.c_ubyte), #const type_t *pt,
    ctypes.c_char_p,                #const char *name = NULL,
    ctypes.POINTER(ctypes.c_ubyte), #const char *cmt = NULL,
    ctypes.POINTER(ctypes.c_ubyte), #const p_list *field_names = NULL,
    ctypes.POINTER(ctypes.c_ubyte), #const p_list *field_cmts = NULL);
]

############################################################
get_numbered_type = g_dll.get_numbered_type
get_numbered_type.argtypes = [
    ctypes.c_void_p,                                    #const til_t *ti,
    ctypes.c_int,                                       #uint32 ordinal,
    ctypes.POINTER(ctypes.c_char_p),     #const type_t **type=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fields=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const char **cmt=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fieldcmts=NULL,
    ctypes.POINTER(ctypes.c_ulong),                     #sclass_t *sclass=NULL
]

set_numbered_type = g_dll.set_numbered_type
set_numbered_type.argtypes = [
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




ITSP = IdaTypeStringParser()
t = ITSP.ImportLocalType(71)
tif = tinfo_t()
print t.fieldcmts
print t.cmt
print tif.deserialize(idaapi.cvar.idati,t.TypeString,t.TypeFields,t.cmt)
print tif
name = ""
print tif.get_type_name(name)
print name
print tif._print(None,idaapi.PRTYPE_MULTI)

tif2 = ctypes.c_ulong()

print c_deserialize_tinfo(byref(tif2),my_til,ctypes.c_char_p(t.TypeString),ctypes.c_char_p(t.TypeFields),ctypes.c_char_p(t.fieldcmts))
ret = qtype()
ret.cur_size = 0
ret.max_size = 0
print c_print_tinfo(byref(ret),ctypes.c_char_p(),0,0,idaapi.PRTYPE_MULTI,byref(tif2),ctypes.c_char_p("aaaa"),ctypes.c_char_p())
print ret.ptr

type_string = qtype()
type_fields = qtype()
type_fieldcmts = qtype()
print  c_serialize_tinfo(byref(type_string),byref(type_fields),byref(type_fieldcmts),byref(tif2),SUDT_FAST|SUDT_TRUNC)
print type_string.ptr.encode("hex")
print t.TypeString.encode("hex")
print type_fields.ptr.encode("hex")
print t.TypeFields.encode("hex")

from __future__ import print_function

import base64
from builtins import chr
from builtins import range
from builtins import object

import ida_kernwin
from idaapi import *
from idc import *
import time
import idaapi
import ida_pro
import idc
from ctypes import *
import ctypes
import pickle
import os, sys
import struct
import collections

#from ida_type_storage.forms import DublicateResolverUI
from ida_type_storage.forms import DublicateResolverUI, ConnectToSQLBase, ChooseProject, ConnectToBase, TypeChooseForm

fSQL = True
if fSQL:
    import sqlite3
else:
    from pymongo import *
    from bson import *

fDebug = False
if fDebug:
    import pydevd_pycharm

class ActionWrapper(idaapi.action_handler_t):
    def __init__(self, id, name, shortcut, menuPath, callback, args = None):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.shortcut = shortcut
        self.menuPath = menuPath
        self.callback = callback
        self.args = args
        self.registerAction()

    def registerAction(self):
        action_desc = idaapi.action_desc_t(
        self.id,        # The action id
        self.name,      # The action text.
        self,           # The action handler.
        self.shortcut,  # Optional: the action shortcut
        "",   # Optional: the action tooltip (available in menus/toolbar)
        -1)      # Optional: the action icon (shows when in menus/toolbars)
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_menu(self.menuPath, self.id, 0):
            return False
        return True

    def unregisterAction(self):
        idaapi.detach_action_from_menu(self.menuPath, self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        if self.args is None:
            self.callback(ctx)
        else:
            self.callback(ctx, self.args)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

############################################################
# Several type-related functions aren't accessibly via IDAPython
# so have to do things with ctypes
idaname = "ida64" if idc.__EA64__ else "ida"
if sys.platform == "win32":
    g_dll = ctypes.windll[idaname + ".wll"] if ida_pro.IDA_SDK_VERSION < 700 else ctypes.windll[idaname + ".dll"]
elif sys.platform == "linux2":
    g_dll = ctypes.cdll["lib" + idaname + ".so"]
elif sys.platform == "darwin":
    g_dll = ctypes.cdll["lib" + idaname + ".dylib"]


class til_t(ctypes.Structure):
    pass

til_t._fields_ = [
        ("name", ctypes.c_char_p),
        ("desc", ctypes.c_char_p),
        ("nbases", ctypes.c_int),
        ("base", ctypes.POINTER(ctypes.POINTER(til_t)))]

wrapperTypeString = b'\x0d\x01\x01'

############################################################
# Specifying function types for a few IDA SDK functions to keep the
# pointer-to-pointer args clear.

c_free_til = g_dll.free_til
c_free_til.argtypes = [
    c_void_p
]

c_new_til = g_dll.new_til
c_new_til.argtyped = [
    c_char_p,                           #const char *name
    c_char_p                            #const char *desc
]
c_new_til.restype = c_void_p

if ida_pro.IDA_SDK_VERSION < 700:
    my_til = ctypes.c_void_p.in_dll(g_dll, 'idati')
else:
    c_get_idati = g_dll.get_idati
    c_get_idati.restype = ctypes.c_longlong
    my_til = c_get_idati()

c_compact_numbered_types = g_dll.compact_numbered_types

c_compact_numbered_types.argtypes = [
            ctypes.c_longlong,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int
        ]

c_get_numbered_type = g_dll.get_numbered_type
c_get_numbered_type.argtypes = [
    ctypes.c_void_p,                                    #const til_t *ti,
    ctypes.c_int,                                       #uint32 ordinal,
    ctypes.POINTER(ctypes.c_char_p),     #const type_t **type=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fields=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const char **cmt=NULL,
    ctypes.POINTER(ctypes.c_char_p),     #const p_list **fieldcmts=NULL,
    ctypes.POINTER(ctypes.c_ulong),                     #sclass_t *sclass=NULL
]

c_set_numbered_type = g_dll.set_numbered_type
c_set_numbered_type.argtypes = [
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


class ui_hooks(ida_kernwin.UI_Hooks):
    
    def ready_to_run(self, *args) -> "void":
        if "type_string_parser" in globals():
            global type_string_parser
            if type_string_parser.add_menu_items():
                print("Failed to initialize IDA Type Storage.")
                type_string_parser.del_menu_items()
                del type_string_parser
            else:
                print("Initialized IDA Type Storage.")


my_ti = None
def get_my_ti():
    global my_ti
    if my_ti is None:
        my_ti = idaapi.get_idati()
    return my_ti

class TinfoReader(object):
    def __init__(self, tp):
        self.pos = 0
        self.tp = tp

    def read_byte(self):
        (result,) = struct.unpack("<B", self.tp[self.pos:self.pos+1])
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
    #print "encode_ordinal_to_string: ordinal %d"%ordinal
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
    stemp.append(ord("#"))
    # for i in range(0,len(enc)):
    #     stemp = stemp + struct.pack("B",enc.pop(-1))
    #print stemp
    #print enc
    enc.reverse()
    #print enc
    stemp = stemp + enc
    return stemp

def decode_ordinal_string(enc):
    if enc[1] == ord("#"):
        ord_num = 0
        i = 0
        fEnd = 0
        str_len = struct.unpack("B",enc[0:1])[0] - 2
        #print len
        for ch in enc[2:]:
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
    (ord_len,) = struct.unpack("B",enc[0])
    ord_len -= 2
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
        if fEnd > 0 or i >= ord_len:
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
    stemp = b""
    for i in range(0,len(enc)):
        stemp = stemp + struct.pack("B",enc.pop(-1))
    return stemp

class IdaTypeStorage(object):

    def __init__(self):
        if fDebug ==True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        self.storage_types_cache = None
        self.OrdinalsMap = collections.OrderedDict()
        self.list_type_library = []
        self.LocalTypeMap = {}
        self.FreeOrdinals = []
        self.storage = None
        self.addmenu_item_ctxs = []
        self.typesNamesInStorage = []
        self.cachedStorage = {}
        self.fResDep = True
        self.storageAddr = None
        self.actions = []
        # self.InsertType = self.InsertTypeNew
        # self.ImportLocalType = self.ImportLocalTypeNew
        # self.Initialise = self.InitialiseNew

    def ReconnectToStorage(self,ctx):
        if self.storage is not None:
            self.storage.close_storage()
            self.storage = None
            print ("Disconnected from storage")
        if self.storage is None:
            if not self.ConnectToStorage():
                return
        return


    def ConnectToStorage(self):
        if fSQL:
            f = ConnectToSQLBase(self.storageAddr)
            r = f.Go()
            f.Free()
            if r:
                self.storageAddr = r
                db = Storage_sqlite(r)
                f = ChooseProject(db.GetAllProjects(),db)
                r1 = f.Go()
                f.Free()
                if r1 is not None:
                    db.connect(r1)
                    self.storage = db
                    return True

        else:
            f = ConnectToBase(self.storageAddr)
            r = f.Go()
            f.Free()
            if r:
                serverIP, port = r
                port = int(port)
                self.storageAddr = (serverIP,port)
                try:
                    client_try = MongoClient(serverIP,port)
                    db = client_try['LocalTypesStorage']
                    coll_names = db.collection_names(include_system_collections = False)
                    client_try.close()
                    f = ChooseProject(coll_names,db)
                    r1 = f.Go()
                    f.Free()
                    #print r1
                    if r1 is not None:
                        self.storage = Storage(serverIP,port,r1)
                        return True
                except:
                    Warning("Could not connect to the storage")
        return False
        #     else:
        #         raise
        # except:
        #     raise NameError("Problem with initialisation type storage")


    def add_menu_items(self):
        ret = ida_kernwin.create_menu("TypeStoragePlugin:Menu", "Type storage","Options")
        if not ret: return 1

        self.actions.append(ActionWrapper("TypeStoragePlugin:doImportTypes","Import types from storage","Shift+i","Type",self.doImportTypes))
        self.actions.append(ActionWrapper("TypeStoragePlugin:doExportTypes","Export types to storage","Shift+g","Type",self.doExportTypes))
        self.actions.append(ActionWrapper("TypeStoragePlugin:ReconnectToStorage","Reconnect","","Type",self.ReconnectToStorage))
        self.actions.append(ActionWrapper("TypeStoragePlugin:doPullAll","Pull all types from storage","Shift-Alt-i","Type",self.doPullAll))
        self.actions.append(ActionWrapper("TypeStoragePlugin:doPushAll", "Push all types to storage", "Shift-Alt-g", "Type",self.doPushAll))
        # self.actions.append(ActionWrapper("TypeStoragePlugin:doCompactNumberedTypes", "Compact local types ordinals", "", "Type storage",self.doCompactNumberedTypes))

        return 0

    def del_menu_items(self):
        for act in self.actions:
            act.unregisterAction()

    def doPushAll(self,ctx):
        print("doPushAll start")
        if fDebug ==True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return
        self.Initialise()
        #sorted_list = self.resolveDependenciesForExport(self.LocalTypeMap.values())
        self.saveToStorage(list(self.LocalTypeMap.values()), True)
        print("All types was pushed successfuly!")

    def doPullAll(self,ctx):
        # if fDebug ==True:
        #     pydevd.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return
        self.Initialise()
        # self.init_storage_cache()
        sorted_list = self.resolveDependencies(self.storage.GetAllNames())
        # c_compact_numbered_types(my_til, 1, 0, 0)
        for t in sorted_list:
            self.InsertType(t,True)
        self.close_storage_cache()


    def doImportTypes(self,ctx):
        self.fResDep = True
        if fDebug ==True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return
        self.Initialise()
        sel_list = self.ChooseTypesFromStorage()
        if sel_list is not None and len(sel_list) > 0:
            t_start = time.time()
            # self.init_storage_cache()
            # fromStorage = self.getFromStorageCached(sel_list)
            if len(sel_list) < 300:
                fromStorage = self.getFromStorage(sel_list)
            else:
                self.init_storage_cache()
                fromStorage = self.getFromStorageCached(sel_list)
            t_delta = time.time() - t_start
            print("doImportTypes: getFromStorage time elapsed = %f" % t_delta)
            if self.fResDep:
                t_start = time.time()
                sorted_list = self.resolveDependencies(fromStorage)
                t_delta = time.time() - t_start
                print("doImportTypes: resolveDependencies time elapsed = %f" % t_delta)
            else:
                sorted_list = fromStorage
            # c_compact_numbered_types(my_til, 1, 0, 0)
            t_start = time.time()
            for t in sorted_list:
                self.InsertType(t)
            self.close_storage_cache()
            t_delta = time.time() - t_start
            print("doImportTypes: InsertTypes time elapsed = %f"%t_delta)
            print ("Imported from storage %d types"%len(sorted_list))

    def doExportTypes(self,ctx):
        self.fResDep = True
        if fDebug == True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return
        t_start = time.time()
        self.Initialise()
        t_delta = time.time() - t_start
        print("doExportTypes: Initialise elapsed time = %f" % t_delta)
        sel_list = self.ChooseLocalTypes()
        if len(sel_list) > 0:
            
            if self.fResDep:
                t_start = time.time()
                sorted_list = self.resolveDependenciesForExport(sel_list)
                t_delta = time.time() - t_start
                print("doExportTypes: resolveDependenciesForExport time elapsed = %f" % t_delta)
            else:
                sorted_list = sel_list
            t_start = time.time()
            self.saveToStorage(sorted_list)
            t_delta = time.time() - t_start
            print("doExportTypes: saveToStorage time elapsed =  %f" % t_delta)
            print ("Exported to storage %d types"%len(sorted_list))

    def doCompactNumberedTypes(self,ctx):
        c_compact_numbered_types(my_til, 1, 0, 0)
    
    def InitTypeLibsList(self):
        self.list_type_library = []
        for idx in range(idaapi.get_idati().nbases):
            type_library = idaapi.get_idati().base(idx)  # idaapi.til_t type
            self.list_type_library.append((type_library, type_library.name, type_library.desc))

    def isStanadardType(self,name):

        for tp in self.list_type_library:
            if idc.__EA64__:
                if get_named_type64(tp[0],name,1):
                    return True
            else:
                if get_named_type(tp[0],name,1):
                    return True
        return False

    def Initialise(self):
        self.InitTypeLibsList()
        # compact_numbered_types(my_til)
        self.LocalTypeMap = collections.OrderedDict()
        self.FreeOrdinals = []
        self.OrdinalsMap = collections.OrderedDict()
        for i in range(1, ida_typeinf.get_ordinal_qty(ida_typeinf.get_idati())):
            name = ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(),i)
            if name:
                #todo: doing something with empty and error types
                
                # tif = tinfo_t()
                # rc = tif.get_numbered_type(idaapi.get_idati(),i)b
                # assert tif.get_size()&0xFFFFFFFF != BADADDR
                # if tif.get_size()&0xFFFFFFFF != BADADDR:
                    #c_compact_numbered_types(my_til, 1, 0, 0)
                ret = ida_typeinf.get_numbered_type(
                    ida_typeinf.get_idati(),
                    i
                )
                typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass = ret
                if typ_type is None:
                    typ_type = b""
                if typ_fields is None:
                    typ_fields = b""
                if typ_cmt is None:
                    typ_cmt = b""
                if typ_fieldcmts is None:
                    typ_fieldcmts = b""
                t = LocalType(name,typ_type,typ_fields,typ_cmt,typ_fieldcmts,typ_sclass, isStandard=self.isStanadardType(name))
                self.LocalTypeMap[name] = t
                #self.OrdinalsMap[name]
                continue
            #self.FreeOrdinals.append(i)


    def ImportLocalType(self,idx):
        name = idc.get_numbered_type_name(idx)
        if name != None and name not in self.LocalTypeMap:
            ret = get_numbered_type(
                idaapi.get_idati(),
                idx
            )
            typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass = ret
            if typ_type is None:
                typ_type = b""
            if typ_fields is None:
                typ_fields = b""
            if typ_cmt is None:
                typ_cmt = b""
            if typ_fieldcmts is None:
                typ_fieldcmts = b""
            return LocalType(name,typ_type,typ_fields,typ_cmt,typ_fieldcmts,typ_sclass, isStandard=self.isStanadardType(name))
        elif name != None:
            return self.LocalTypeMap[name]
        return None

    def InsertType(self,type_obj,fReplace = False):
        print("Insert type %s." % type_obj.name)
        if self.getTypeOrdinal(type_obj.name) != 0:
            idx = self.getTypeOrdinal(type_obj.name)
            t = self.ImportLocalType(idx)
            if not t.TypeFields and t.is_sue():
                fReplace = True
            if t.isEqual(type_obj) or type_obj.TypeString == wrapperTypeString:
                return 1
            if not fReplace:
                type_obj = self.DuplicateResolver(t,type_obj,False)
        elif len(self.FreeOrdinals) > 0:
            idx = self.FreeOrdinals.pop(0)
        else:
            idx = alloc_type_ordinals(idaapi.get_idati(),1)
        tif = idaapi.tinfo_t()
        ret = tif.deserialize(idaapi.get_idati(),type_obj.GetTypeString(),type_obj.TypeFields,type_obj.fieldcmts)
        if  not ret:
            warning("Error on tinfo deserilization, type name = %s, ret = %d"%(type_obj.name,ret))
            ret = -1
        else:
            ret = tif.set_numbered_type(idaapi.get_idati(),idx,0x4,type_obj.name)
        del tif
        # ret = idaapi.set_numbered_type(
        #     my_ti,
        #     idx,
        #     0x4,
        #     type_obj.name,
        #     type_obj.GetTypeString(),
        #     type_obj.TypeFields,
        #     type_obj.cmt,
        #     type_obj.fieldcmts
        # )
        # print "Insert type %s. ret = %d"%(type_obj.name,ret)
        if (ida_pro.IDA_SDK_VERSION < 700 and ret != 1) or (ida_pro.IDA_SDK_VERSION >= 700 and ret != 0):
            print ("bad insert: %s; ret = %d"%(type_obj.name,ret))
        return ret


    def getTypeOrdinal(self,name):
        my_ti = get_my_ti()
        my_ti = ida_typeinf.get_idati()
        return ida_typeinf.get_type_ordinal(my_ti,name)

    def ChooseLocalTypes(self):
        if len(self.LocalTypeMap) == 0:
            self.Initialise()
        f = TypeChooseForm(self.LocalTypeMap,True)
        r = f.Go()
        f.Free()
        if r != None and len(r[0]) != 0:
            selected, fResDep = r
            self.fResDep = fResDep
        else:
            selected = ""
        #print selected
        #print len(selected)
        return selected


    def ChooseTypesFromStorage(self):
        f = TypeChooseForm(self.storage.GetAllNames(),False,self.storage)
        r = f.Go()
        f.Free()
        if r != None and len(r[0]) != 0:
            selected, fResDep = r
            self.fResDep = fResDep
        else:
            selected = ""
        return selected

    def saveToStorage(self,typesList,fReplace = False):
        l = []
        for t in typesList:
            if self.storage.isExist(t.name):
                tp = self.getFromStorage([t.name])[0]
                if not t.isEqual(tp):
                    if fReplace:
                        t1 = t
                    else:
                        t1 = self.DuplicateResolver(tp,t,True)
                    if not t1.isEqual(tp):
                        self.storage.updateType(t1.name,t1)
                        #self.cachedStorage[t1.name] = t1
                        #print "Edited type updated"
                    # raise NameError("saveToStorage: Duplicated type name (%s) with differ body"%t.name)
                    else:
                        print ("Edited type don't have changes")
                continue
            l.append(t.to_iter())
        self.storage.putManyToStorage(l)
            #self.cachedStorage[t.name] = t

    def getFromStorage(self,typesListNames):
        if self.storage_types_cache:
            return self.getFromStorageCached(typesListNames)
        typesList = []
        for name in typesListNames:
            t = self.storage.getFromStorage(name)
            if t is None:
                raise NameError("getFromStorage: Type name (%s) not in the storage"%name)
            typesList.append(t)
        return typesList

    def init_storage_cache(self):
        self.storage_types_cache = self.storage.getAllTypes()
        
    def close_storage_cache(self):
        self.storage_types_cache = None
    
    def getFromStorageCached(self, typesListNames):
        ret = []
        if self.storage_types_cache:
            for name in typesListNames:
                if name in self.storage_types_cache:
                    ret.append(self.storage_types_cache[name])
        else:
            ret = self.getFromStorage(typesListNames)
        return ret

    def resolveDependencies(self,startList):
        toResolve = []
        toResolveNames = []
        #print "resolveDependencies: startList", startList
        prev_len = -1
        if type(startList[0]) == str or type(startList[0]) == str:
            self.init_storage_cache()
            startList = self.getFromStorage(startList)
        while len(toResolve) != prev_len:
            prev_len = len(toResolve)
            for t in startList:
                for name in t.depends:
                    if name not in toResolveNames:
                        toResolveNames.append(name)
                        toResolve.append(self.getFromStorage([name])[0])
                if t.name not in toResolveNames:
                    toResolveNames.append(t.name)
                    toResolve.append(t)

            startList = toResolve
        sortedList = []
        #print "resolveDependencies: toResolveNames", toResolve
        # toResolveNames = toResolve
        # toResolve = self.getFromStorage(toResolve)
        prev_len = len(toResolve)
        sortedListNames = []


        while len(toResolve) > 0:
            for t in toResolve:
                if len(t.depends) == 0:
                    sortedList.append(t)
                    toResolve.remove(t)
                    sortedListNames.append(t.name)
                    toResolveNames.remove(t.name)
                else:
                    if self.checkExistence(t.depends,sortedListNames):
                        sortedList.append(t)
                        toResolve.remove(t)
                        sortedListNames.append(t.name)
                        toResolveNames.remove(t.name)
            if prev_len == len(toResolve):
                for t in toResolve:
                    for name in t.depends:
                        if self.checkExistence([name],sortedListNames):
                            continue
                        elif self.checkExistence([name],toResolveNames):
                            sortedList.append(self.addTypeWrapper(name))
                            sortedListNames.append(name)
                            continue
                        else:
                            raise NameError("resolveDependencies: Unresolved type dependencies %s"%name)
            prev_len = len(toResolve)
        return sortedList

    def getFromLocalTypesMap(self,name_list):
        type_list = []
        for name in name_list:
            if (type(name) == str or type(name) == str) and name in self.LocalTypeMap:
                type_list.append(self.LocalTypeMap[name])
            else:
                raise NameError("getLocalTypesFromMap: missing type %s"%name)

        return type_list

    def resolveDependenciesForExport(self,startList):
        toResolve = []
        toResolveNames = []
        #print "resolveDependenciesForExport: startList", startList
        prev_len = -1
        while len(toResolve) != prev_len:
            prev_len = len(toResolve)
            if type(startList[0]) == str or type(startList[0]) == str:
                startList = self.getFromLocalTypesMap(startList)
            for t in startList:
                for name in t.depends:
                    if name not in toResolve:
                        toResolve.append(name)
                if t.name not in toResolve:
                    toResolve.append(t.name)
            startList = toResolve
        sortedList = []
        #print "resolveDependenciesForExport: toResolveNames", toResolve
        toResolveNames = toResolve
        toResolve = self.getFromLocalTypesMap(toResolve)
        prev_len = len(toResolve)
        sortedListNames = []


        # while len(toResolve) > 0:
        #     for t in toResolve:
        #         if len(t.depends) == 0:
        #             sortedList.append(t)
        #             toResolve.remove(t)
        #             sortedListNames.append(t.name)
        #             toResolveNames.remove(t.name)
        #         else:
        #             if self.checkExistence(t.depends,sortedListNames):
        #                 sortedList.append(t)
        #                 toResolve.remove(t)
        #                 sortedListNames.append(t.name)
        #                 toResolveNames.remove(t.name)
        #     if prev_len == len(toResolve):
        #         for t in toResolve:
        #             for name in t.depends:
        #                 if self.checkExistence([name],sortedListNames):
        #                     continue
        #                 elif self.checkExistence([name],toResolveNames):
        #                     sortedList.append(self.addTypeWrapper(name))
        #                     sortedListNames.append(name)
        #                     continue
        #                 else:
        #                     raise NameError("resolveDependenciesForExport: Unresolved type dependencies %s"%name)
        #     prev_len = len(toResolve)
        # return sortedList
        return toResolve


    def addTypeWrapper(self,name):
        global wrapperTypeString
        return LocalType(name,wrapperTypeString)


    def checkExistence(self,name_list,target_list):
        for name in name_list:
            if name not in target_list:
                return False
        return True


    def allTypeToStorage(self):
        toStorage = []
        self.Initialise()
        for t in list(self.LocalTypeMap.values()):
            toStorage.append(t)
        self.saveToStorage(toStorage)

    def getAllTypesFromStorage(self):
        names = self.storage.GetAllNames()
        return self.getFromStorage(names)


    def allTypeFromStorage(self):
        fromStorage = self.getAllTypesFromStorage()
        sorted_list = self.resolveDependencies(fromStorage)
        #print sorted_list
        # c_compact_numbered_types(my_til, 1, 0, 0)
        for t in sorted_list:
            self.InsertType(t)

    def FixSTLNames(self,types_list, fFromStorage = False):
        fixed_names = {}
        if type(types_list) == str or type(types_list) == str:
                if fFromStorage:
                    types_list = self.getFromStorage(types_list)
                else:
                    types_list = self.getFromLocalTypesMap(types_list)
        for t in types_list:
            p = re.compile(r'\w*(<.*>)\w*')
            tok =  p.findall(t.name)
            if len(tok) > 0:
                if tok[0].find(",") == -1:
                    t.name.replace(tok[0],"") +"_" + tok[0][1:tok[0].find(",")].rstrip(" *").strip(" *").replace(" ","_")




    def DuplicateResolver(self,t1,t2,fToStorage = False):
        f = DublicateResolverUI(t1.print_type(), t2.print_type(), fToStorage)
        while True:
            f.Go()
            if f.sel == 1:
                return t1
            elif f.sel == 2:
                return t2
            else:
                r = idc.parse_decl(f.selText, 0x008E)
                if r is not None:
                    return LocalType(r[0], r[1], r[2])

    def InsertTypeOld(self, type_obj, fReplace=False):
        my_ti = get_my_ti()
        my_ti = idaapi.get_idati()
        # print "InsertType:",type(type_obj.name), type_obj.name
        # print "InsertType: idx = %d"%self.getTypeOrdinal(type_obj.name.encode("ascii"))
        # print "InsertType: idx = %d"%self.get_type_ordinal(my_ti,type_obj.name.encode("ascii"))
        if self.getTypeOrdinal(type_obj.name) != 0:
            # print "InsertType: getTypeOrdinal"
            idx = self.getTypeOrdinal(type_obj.name)
            t = self.ImportLocalType(idx)
            if (t.TypeFields is None or t.TypeFields == "") and t.is_sue():
                fReplace = True
            if t.isEqual(type_obj) or type_obj.TypeString == wrapperTypeString:
                return 1
            if not fReplace:
                type_obj = self.DuplicateResolver(t, type_obj, False)
        elif len(self.FreeOrdinals) > 0:
            # print "InsertType: FreeOrdinals.pop"
            idx = self.FreeOrdinals.pop(0)
        else:
            # print "InsertType: alloc_type_ordinals"
            idx = alloc_type_ordinals(my_ti, 1)
        # print "InsertType: type_obj.parsedList = ", type_obj.parsedList
        # print "InsertType: idx = %d"%idx
        typ_type = ctypes.c_char_p(type_obj.GetTypeString())
        # if len(type_obj.TypeFields) == 0:
        #     typ_fields = 0
        # else:
        typ_fields = ctypes.c_char_p(type_obj.TypeFields)
        # if len(type_obj.cmt) == 0:
        #     typ_cmt = 0
        # else:
        typ_cmt = ctypes.c_char_p(type_obj.cmt)
        # if len(type_obj.fieldcmts) == 0:
        #     typ_fieldcmts = 0
        # else:
        typ_fieldcmts = ctypes.c_char_p(type_obj.fieldcmts)
        # print type_obj.print_type()
        if type(type_obj.sclass) == int:
            type_obj.sclass = ctypes.c_ulong(type_obj.sclass)
        ret = 1
        ret = c_set_numbered_type(
            my_til,
            idx,
            0x4,
            ctypes.c_char_p(type_obj.name),
            typ_type,
            typ_fields,
            typ_cmt,
            typ_fieldcmts,
            ctypes.byref(type_obj.sclass)
        )

        # print "InsertType: ret = %d"%ret
        if (ida_pro.IDA_SDK_VERSION < 700 and ret != 1) or (ida_pro.IDA_SDK_VERSION >= 700 and ret != 0):
            print ("bad insert: %s; ret = %d" % (type_obj.name, ret))
        return ret

    def ImportLocalTypeOld(self, idx):
        global my_til
        name = idc.get_numbered_type_name(idx)
        if name != None and name not in self.LocalTypeMap:
            typ_type = ctypes.c_char_p()
            typ_fields = ctypes.c_char_p()
            typ_cmt = ctypes.c_char_p()
            typ_fieldcmts = ctypes.c_char_p()
            typ_sclass = ctypes.c_ulong()
            ret = c_get_numbered_type(
                my_til,
                idx,
                ctypes.byref(typ_type),
                ctypes.byref(typ_fields),
                ctypes.byref(typ_cmt),
                ctypes.byref(typ_fieldcmts),
                ctypes.byref(typ_sclass)
            )
            typ_type = typ_type.value
            typ_fields = typ_fields.value
            typ_cmt = typ_cmt.value
            typ_fieldcmts = typ_fieldcmts.value
            return LocalType(name, typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass.value, isStandard=self.isStanadardType(name))
        elif name != None:
            return self.LocalTypeMap[name]
        return None

    def InitialiseOld(self):
        global my_til
        my_ti = idaapi.get_idati()
        self.InitTypeLibsList()
        # compact_numbered_types(my_til)
        self.LocalTypeMap = collections.OrderedDict()
        self.FreeOrdinals = []
        self.OrdinalsMap = collections.OrderedDict()
        for i in range(1, idc.get_ordinal_qty()):
            # for i in range(12114, 12115):
            name = idc.get_numbered_type_name(i)
            # print "Ordinal = %d; Type name = %s"%(i,name)
    
            if name != None:
                tif = tinfo_t()
                rc = tif.get_numbered_type(my_ti, i)
                if tif.get_size() != BADADDR:
                    c_compact_numbered_types(my_til, 1, 0, 0)
                    typ_type = ctypes.c_char_p()
                    typ_fields = ctypes.c_char_p()
                    typ_cmt = ctypes.c_char_p()
                    typ_fieldcmts = ctypes.c_char_p()
                    typ_sclass = ctypes.c_ulong()
                    ret = c_get_numbered_type(
                        my_til,
                        i,
                        ctypes.byref(typ_type),
                        ctypes.byref(typ_fields),
                        ctypes.byref(typ_cmt),
                        ctypes.byref(typ_fieldcmts),
                        ctypes.byref(typ_sclass)
                    )
                    typ_type = typ_type.value
                    if typ_type == None:
                        typ_type = ""
                    # print typ_type
                    typ_fields = typ_fields.value
                    if typ_fields == None:
                        typ_fields = ""
                    typ_cmt = typ_cmt.value
                    if typ_cmt == None:
                        typ_cmt = ""
                    typ_fieldcmts = typ_fieldcmts.value
                    if typ_fieldcmts == None:
                        typ_fieldcmts = ""
                    typ_sclass = typ_sclass.value
                    t = LocalType(name, typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass, isStandard=self.isStanadardType(name))
                    self.LocalTypeMap[name] = t
                    # self.OrdinalsMap[name]
                    continue
            # self.FreeOrdinals.append(i)
        # print len(self.LocalTypeMap)
        # f = open("F:\IdaTextTypesParser\cache.dat","wb")
        # pickle.dump(self.LocalTypeMap,f)
        # f.close()


class Storage_sqlite(object):
    actual_cols = ['name', 'TypeString', 'TypeFields', 'cmt', 'fieldcmts', 'sclass', 'parsedList', 'depends',
                   'depends_ordinals', "flags"]

    def __init__(self, db_name, project_name=""):
        self.cursor = None
        self.db_name = db_name
        self.project_name = project_name
        self.conn = None
        if self.project_name != "" and not self.isTableExist(self.project_name):
            self.request(
                r"CREATE TABLE '%s' (name text, TypeString text, TypeFields text, cmt text, fieldcmts text, sclass text, parsedList text, depends text, depends_ordinals text, flags integer)" % (
                self.project_name))
        elif self.project_name != "" and not self.isActual():
            self.update_table()

    def isTableExist(self, name):
        return True if len(
            self.request(r"SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (name,))) == 1 else False

    def connect(self, project_name):
        self.project_name = project_name
        if self.project_name != "" and not self.isTableExist(self.project_name):
            self.request(
                r"CREATE TABLE '%s' (name text, TypeString text, TypeFields text, cmt text, fieldcmts text, sclass text, parsedList text, depends text, depends_ordinals text, flags integer)" % (
                self.project_name))
        elif self.project_name != "" and not self.isActual():
            self.update_table()

    def request(self, req_str, vals=()):
        if type(vals) != tuple:
            vals = (vals,)
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        if len(vals) == 0:
            res = c.execute(req_str)
        else:
            res = c.execute(req_str, vals)
        res = res.fetchall()
        conn.commit()
        conn.close()
        return res
    
    def start_transactions(self):
        if self.conn:
            self.end_transactions()
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        
    def parting_request(self, req_str, vals=()):
        if self.conn:
            if type(vals) != tuple:
                vals = (vals,)
            # c = self.conn.cursor()
            if len(vals) == 0:
                res = self.cursor.execute(req_str)
            else:
                res = self.cursor.execute(req_str, vals)
            res = res.fetchall()
            return res
        return None
    
    def end_transactions(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()
            self.conn = None
            self.cursor = None

    def modify_ret(self, res):
        if len(res) > 0 and len(res[0]) == 1:
            ret = []
            for el in res:
                if type(el) != int:
                    ret.append(el[0])
            return ret
        elif len(res) == 1 and len(res[0]) > 1:
            ret = []
            for el in res[0]:
                if type(el) != int:
                    ret.append(el)
            return ret
        return res

    def GetAllProjects(self):
        return self.modify_ret(self.request(r"SELECT name FROM sqlite_master WHERE type='table'"))

    def GetAllNames(self, mask=15):
          return self.modify_ret(self.request(r"SELECT name FROM '%s' WHERE (flags == 0 OR (((flags & %d) != 0) and (%d == 8 OR (flags & 8) == %d)))" % (self.project_name,mask&7,mask&8,mask&8)))

        # if mask&8 == 0:
        #     ret = [x for n in self.modify_ret(self.request(r"SELECT name FROM %s WHERE (flags == 0 OR (flags & 8) == 0)" % (self.project_name, mask&7))) if n in ret]

    def deleteProject(self, name=""):
        if name == "":
            name = self.project_name
        self.request(r"drop table '%s'" % (name))
        self.project_name = ""

    def close_storage(self):
        pass

    def to_dict(self, res):
        ser_dic = collections.OrderedDict()
        ser_dic['name'] = res[0]
        ser_dic['TypeString'] = res[1]
        ser_dic['TypeFields'] = res[2]
        ser_dic['cmt'] = res[3]
        ser_dic['fieldcmts'] = res[4]
        ser_dic['sclass'] = pickle.loads(base64.b64decode(res[5]))
        ser_dic['parsedList'] = pickle.loads(base64.b64decode(res[6]))
        ser_dic['depends'] = pickle.loads(base64.b64decode(res[7]))
        ser_dic['depends_ordinals'] = pickle.loads(base64.b64decode(res[8]))
        ser_dic['flags'] = res[9]
        return ser_dic

    def putManyToStorage(self,elems_list):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        res = c.executemany(r"INSERT INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" % self.project_name,elems_list)
        res = res.fetchall()
        conn.commit()
        conn.close()
        return res
    
    def putToStorage(self, t):
        # print "Name = %s; flag = %d"%(t.name,t.flags)
        ser_dic = t.to_dict()
        try:
            self.request(r"INSERT INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" % self.project_name, (
            ser_dic['name'], ser_dic['TypeString'], ser_dic['TypeFields'], ser_dic['cmt'], ser_dic['fieldcmts'],
            ser_dic["sclass"],
            ser_dic["parsedList"],
            ser_dic["depends"],
            ser_dic["depends_ordinals"],
            ser_dic['flags']))
        except:
            Warning("Exception on sqlite putToStorage")

    def getFromStorage(self, name):
        if type(name) == bytes:
            name = name.decode("utf-8")
        try:
            res = self.request(r"SELECT * FROM '%s' WHERE name=?" % self.project_name, (name,))
            if len(res) == 0:
                return None
            elif len(res) > 1:
                raise NameError("getFromStorage: Type duplication or error. Count = %d" % len(res))
            else:
                # print self.to_dict(res[0])
                return LocalType().from_dict(self.to_dict(res[0]))
        except:
            Warning("Exception on sqlite getFromStorage")
            return None

    def getAllTypes(self):
        types = collections.OrderedDict()
        res = self.request(r"SELECT * FROM '%s'" % self.project_name)
        for elem in res:
            t = LocalType().from_dict(self.to_dict(elem))
            types[t.name] = t
        return types
        
    def isExist(self, name):
        res = self.request(r"SELECT * FROM '%s' WHERE name=?" % self.project_name, (name,))
        if len(res) == 0:
            return False
        elif len(res) == 1:
            return True
        else:
            raise NameError("isExist: Type duplication or error. Count = %d" % (len(res)))

    def updateType(self, name, t):
        ser_dic = t.to_dict()
        try:
            self.request(
                r"UPDATE '%s' SET name = ?, TypeString = ?, TypeFields = ?, cmt = ?, fieldcmts = ?, sclass = ?, parsedList = ?, depends = ?, depends_ordinals = ?, flags = ? WHERE name = ?" % (
                self.project_name), (ser_dic['name'], ser_dic['TypeString'], ser_dic['TypeFields'], ser_dic['cmt'], ser_dic['fieldcmts'],
                                        ser_dic["sclass"],
                                        ser_dic["parsedList"],
                                        ser_dic["depends"],
                                        ser_dic["depends_ordinals"],
                                        ser_dic['flags'],
                                        name)
                                        )
            return True
        except:
            Warning("Exception on sqlite updateType")
            return False

    def isActual(self):
        if self.project_name != "":
            curr_cols = []
            for inf in self.modify_ret(self.request(r"PRAGMA table_info('%s')" % self.project_name)):
                curr_cols.append(inf[1] if type(inf[1]) == str else inf[1].decode("utf-8"))
            return curr_cols == self.actual_cols
        return True

    def update_table(self):
        self.request(r"ALTER TABLE '%s' ADD COLUMN flags INTEGER DEFAULT 0;"%self.project_name)
        ret = self.request(r"SELECT name,TypeString FROM '%s'" % self.project_name)
        for name, ts in ret:
            flag = 0
            ts = ts.decode("base64")
            if LocalType.is_su_static(ts):
                flag = 1
            elif LocalType.is_enum_static(ts):
                flag = 2
            elif LocalType.isnt_sue_static(ts):
                flag = 4
            else:
                raise NameError("Unknown type of LocalType")
            self.request(r"UPDATE '%s' SET flags = ? WHERE name = ?"%self.project_name, (flag, name))



class Storage(object):
    def __init__(self,ip = 'localhost',port = 27017 ,target_collection = "main_storage"):
        self.client = MongoClient(ip, port)
        self.db = self.client["LocalTypesStorage"]
        self.collection = self.db[target_collection]
        #self.cache ={}

    def putToStorage(self,t):
        self.collection.insert_one(t.to_dict())
        res = self.collection.find({'name':t.name})
        if res.count() != 1:
            #self.cache[t.name] = res[0]
        # else:
            raise NameError("putToStorage: Putting error. Count = %d. Type %s"%(res.count(),t.name))


    def clearStorage(self):
        self.collection.drop()

    def close_storage(self):
        self.client.close()

    def checkEquality(self,t):
        ser_dic = t.to_dict()
        res = self.collection.find({'name':ser_dic['name']})
        if res.count() == 1:
            t1 = res[0]
            if t1['parsedList'] == ser_dic['parsedList']:
                if t1['TypeFields'] == ser_dic['TypeFields']:
                    if t1['cmt'] == ser_dic['cmt']:
                        if t1['fieldcmts'] == ser_dic['fieldcmts']:
                            return True
        elif res.count() == 0:
            return False
        else:
            raise NameError("checkEquality: Type duplication or error. Count = %d"%(res.count()))
        return False

    def getFromStorage(self,name):
        # if name in self.cache:
        #     return LocalType().from_dict(self.cache[name])
        res = self.collection.find({"name":name})
        if res.count() == 1:
            #self.cache[name] = res[0]
            return LocalType().from_dict(res[0])
        elif res.count() == 0:
            return None
        else:
            raise NameError("getFromStorage: Type duplication or error. Count = %d"%(res.count()))

    def isExist(self,name):
        res = self.collection.find({"name":name})
        if res.count() == 1:
            return True
        elif res.count() == 0:
            return False
        else:
            raise NameError("isExist: Type duplication or error. Count = %d"%(res.count()))

    def updateType(self,name,t):
        ret = self.collection.replace_one({'name':name},t.to_dict())
        if ret.matched_count == 1:
            #self.cache[name] = t.to_dict()
            return True
        elif ret.matched_count == 0:
            return False
        else:
            raise NameError("updateType: Type duplication or error. Count = %d"%(ret.count()))

    def GetAllNames(self):
        names = []
        # if len(self.cache) == 0:
        for t in self.collection.find():
            names.append(t['name'])
                # self.cache[t['name']] = t
        # else:
        #     for name in self.cache.keys():
        #         names.append(name)
        return names

    def GetAllTypes(self):
        names = self.GetAllNames()
        types = []
        for name in names:
            types.append(self.getFromStorage(name))
        return types

    def deleteProject(self,name):
        self.db[name].drop()

class LocalType(object):

    # Flags = {
    #     "struct":1,
    #     "enum":2,
    #     "other":4,
    #     "standard":8
    # }

    def __init__(self, name=b"", TypeString=b"", TypeFields=b"", cmt=b"", fieldcmts=b"", sclass=0, parsedList=None, depends=None, isStandard=False):
        self.TypeString = TypeString
        self.TypeFields = TypeFields
        self.cmt = cmt
        self.fieldcmts = fieldcmts if type(fieldcmts) == bytes else fieldcmts.encode("utf-8")
        self.sclass = sclass
        self.name = name
        self.parsedList = [] if parsedList is None else parsedList
        self.depends = [] if depends is None else depends
        self.depends_ordinals = []
        self.flags = 8 if isStandard else 0
        # print "Type string: %s"%self.TypeString.encode("HEX")
        if self.TypeString != b"":
            self.parsedList = self.ParseTypeString(self.TypeString)
        if self.TypeString != b"":
            if self.is_su():
                self.flags |= 1
            elif self.is_enum():
                self.flags |= 2
            elif self.isnt_sue():
                self.flags |= 4

    # def __init__(self, idx):
    #     self.name = None
    #     self.parsedList = []
    #     self.TypeString = None
    #     self.TypeFields = None
    #     self.cmt = None
    #     self.fieldcmts = None
    #     self.sclass = None
    #     self.depends = []

    @staticmethod
    def find_type_by_name(name):
        my_ti = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(my_ti,name)

    def GetTypeString(self):
        ti = idaapi.get_idati()
        #print "GetTypeString: name %s"%self.name
        the_bytes = []
        for thing in self.parsedList:
            if type(thing) == int:  # if it's a byte, just put it back in
                the_bytes.append(thing)
            elif len(thing) == 1:
                if list(thing.keys())[0] == "local_type":
                    the_bytes.append(ord("="))  # a type starts with =
                #print type(thing["local_type"]),thing["local_type"]
                ordinal = ida_typeinf.get_type_ordinal(ti,list(thing.values())[0])  # get the ordinal of the Local Type based on its name
                if ordinal > 0:
                    the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
                else:
                    raise NameError("Depends local type not in IDB")
            else:
                raise NameError("Wrong depend record for type: %s!"%self.name)
        packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
        return packed

    def ParseTypeString(self,type_string):
        if fDebug ==True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        tp = TinfoReader(type_string)
        ti = idaapi.get_idati()
        # print idc_print_type(type_, fields, "fun_name", 0)
        # print type_.encode("string_escape")
        output = []
        """
        Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
        Pass all other bytes through as-is.
        """
        while tp.keep_going():
            a_byte = tp.read_byte()
            unwritten_bytes = [a_byte]
            if a_byte == ord("=") and tp.pos < len(tp.tp):  # a type begins
                ordinal_length = tp.read_byte()
                if tp.pos < len(tp.tp) and len(tp.tp) - (tp.pos + ordinal_length - 1) >= 0:
                    number_marker = tp.read_byte()
                    if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
                        ordinal = decode_ordinal_string(struct.pack("B",ordinal_length) + b"#" + tp.read_string(ordinal_length-2))
                        t = idc.get_numbered_type_name(ordinal)
                        output.append({"local_type": t})
                        if t not in self.depends:
                            self.depends.append(t)
                            self.depends_ordinals.append(ordinal)
                        continue
                    else:
                        unwritten_bytes.append(ordinal_length)
                        unwritten_bytes.append(number_marker)
                else:
                    unwritten_bytes.append(ordinal_length)
            elif a_byte == ord("#") and ((len(output) >= 4 and output[-4:-1] == [0x0A,0x0D,0x01]) or (len(output) >= 3 and  output[-3:-1] == [0x0D,0x01])):
                ordinal_length = output[-1]
                output.pop(-1)
                ordinal = decode_ordinal_string(struct.pack("B", ordinal_length) + b"#" + tp.read_string(ordinal_length - 2))
                t = idc.get_numbered_type_name(ordinal)
                output.append({"rare_local_type": t})
                if t not in self.depends:
                    self.depends.append(t)
                    self.depends_ordinals.append(ordinal)
                continue
            
            output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is

        return output

    def to_dict(self):
        ser_dic = collections.OrderedDict()
        ser_dic['name'] = self.name
        ser_dic['TypeString'] = base64.b64encode(self.TypeString)
        ser_dic['TypeFields'] = base64.b64encode(self.TypeFields)
        ser_dic['cmt'] = base64.b64encode(self.cmt)
        ser_dic['fieldcmts'] = base64.b64encode(self.fieldcmts)
        ser_dic['sclass'] = base64.b64encode(pickle.dumps(self.sclass))
        ser_dic['parsedList'] = base64.b64encode(pickle.dumps(self.parsedList))
        ser_dic['depends'] = base64.b64encode(pickle.dumps(self.depends))
        ser_dic['depends_ordinals'] = base64.b64encode(pickle.dumps(self.depends_ordinals))
        ser_dic['flags'] = self.flags
        return ser_dic

    def to_iter(self):
        return self.name, base64.b64encode(self.TypeString), base64.b64encode(self.TypeFields),base64.b64encode(self.cmt),base64.b64encode(self.fieldcmts), base64.b64encode(pickle.dumps(self.sclass)), base64.b64encode(pickle.dumps(self.parsedList)), base64.b64encode(pickle.dumps(self.depends)), base64.b64encode(pickle.dumps(self.depends_ordinals)), self.flags
    
    def from_dict(self,ser_dic):
        self.name = ser_dic['name']
        self.TypeString = base64.b64decode(ser_dic['TypeString'])
        # print "from_dict; TypeString = %s"%self.TypeString
        self.TypeFields = base64.b64decode(ser_dic['TypeFields'])
        self.cmt = base64.b64decode(ser_dic['cmt'])
        self.fieldcmts = base64.b64decode(ser_dic['fieldcmts'])
        self.sclass = int(ser_dic['sclass'])
        self.parsedList = ser_dic['parsedList']
        self.depends = ser_dic['depends']
        self.depends_ordinals = ser_dic['depends_ordinals']
        # self.sclass = ctypes.c_ulong(self.sclass)
        self.flags = ser_dic['flags']
        return self

    def print_type(self):
        ret = idaapi.idc_print_type(self.GetTypeString(),self.TypeFields,self.name,idaapi.PRTYPE_MULTI|idaapi.PRTYPE_TYPE)
        if ret is None:
            return ""
        i = 0
        ret = ret.strip()
        return ret

    def is_standard(self):
        return self.flags&8 == 8

    def isEqual(self,t):
        if self.parsedList == t.parsedList \
                and self.TypeFields == t.TypeFields \
                and self.name == t.name:
            return True
        return False

    def is_complex(self):
        return self.TypeString[0] & TYPE_BASE_MASK == BT_COMPLEX

    def is_typedef(self):
        return self.TypeString[0]&TYPE_FULL_MASK == BTF_TYPEDEF

    def is_sue(self):
        return self.is_complex() and not self.is_typedef()

    def isnt_sue(self):
        return not self.is_sue()

    def is_su(self):
        return self.is_complex() and not self.is_typedef() and not self.is_enum()

    def is_paf(self):
        t = self.TypeString[0]&TYPE_BASE_MASK
        return (t >= BT_PTR )&(t <= BT_FUNC)

    def is_func(self):
        return self.TypeString[0]&TYPE_BASE_MASK == BT_FUNC

    def is_struct(self):
        return self.TypeString[0]&TYPE_FULL_MASK == BTF_STRUCT

    def is_union(self):
        return self.TypeString[0]&TYPE_FULL_MASK == BTF_UNION

    def is_enum(self):
        return self.TypeString[0]&TYPE_FULL_MASK == BTF_ENUM

    def is_ptr(self):
        return  self.TypeString[0]&TYPE_FULL_MASK == BT_PTR


    @staticmethod
    def is_complex_static(TypeString):
        return TypeString[0] & TYPE_BASE_MASK == BT_COMPLEX

    @staticmethod
    def is_typedef_static(TypeString):
        return TypeString[0]&TYPE_FULL_MASK == BTF_TYPEDEF

    @staticmethod
    def is_sue_static(TypeString):
        return LocalType.is_complex_static(TypeString) and not LocalType.is_typedef_static(TypeString)

    @staticmethod
    def isnt_sue_static(TypeString):
        return not LocalType.is_sue_static(TypeString)

    @staticmethod
    def is_su_static(TypeString):
        return LocalType.is_complex_static(TypeString) and not LocalType.is_typedef_static(TypeString) and not LocalType.is_enum_static(TypeString)

    @staticmethod
    def is_paf_static(TypeString):
        t = TypeString[0]&TYPE_BASE_MASK
        return (t >= BT_PTR )&(t <= BT_FUNC)

    @staticmethod
    def is_func_static(TypeString):
        return TypeString[0]&TYPE_BASE_MASK == BT_FUNC

    @staticmethod
    def is_struct_static(TypeString):
        return TypeString[0]&TYPE_FULL_MASK == BTF_STRUCT

    @staticmethod
    def is_union_static(TypeString):
        return TypeString[0]&TYPE_FULL_MASK == BTF_UNION

    @staticmethod
    def is_enum_static(TypeString):
        return TypeString[0]&TYPE_FULL_MASK == BTF_ENUM




class IDATypeStoragePlugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "Single repository for types."
    help = "Single repository for types."
    wanted_name = "IDA Type Storage"
    wanted_hotkey = ""

    def init(self):
        # Only Intel x86/x86-64 are supported
        print ("Enter IDATypeStorage.init()")
        global type_string_parser
        #type_string_parser = None
        self.hook =  ui_hooks()
        self.hook.hook()

        # Check if already initialized
        #print not 'type_string_parser' in globals()
        if not 'type_string_parser' in globals():

            type_string_parser = IdaTypeStorage()


        return idaapi.PLUGIN_KEEP


    def run(self, arg):
        pass

    def term(self):
        global type_string_parser
        self.hook.unhook()
        if 'type_string_parser' in globals() and type_string_parser is not None:
            if type_string_parser.storage is not None:
                type_string_parser.storage.close_storage()
                type_string_parser.storage = None
            del type_string_parser

def PLUGIN_ENTRY():
    return IDATypeStoragePlugin()

def manualTypeCopy(dest, destOff, destLen, src):
    '''Copies an IDA type 'string' to the given location'''
    i = 0
    while (i+destOff) < destLen:
        dest[i+destOff] = chr(src[i])
        if (src[i] == 0) or (src[i] == '\x00'):
            break
        i += 1

# f = open('F:\IdaTextTypesParser\log.txt','w+')
# for idx in range(1,2):
#     print idx
#     f.write(str(idx))
#     f.write("\n")
#     f.write(GetLocalTypeName(idx))
#     f.write("\n")
#     typestring, fields = idc_get_local_type_raw(idx)
#     name = GetLocalTypeName(idx)
#
#     temp = 'type: '
#     for ch in typestring:
#         temp = temp + ch.encode('hex') + ' '
#     print temp
#     f.write(temp)
#     f.write("\n")
#     print typestring.__repr__()
#     f.write(typestring.__repr__())
#     f.write("\n")
#     if fields != None:
#         temp = 'fields: '
#         for ch in fields:
#             temp = temp + ch.encode('hex') + ' '
#         print temp
#         f.write(temp)
#         f.write("\n")
#         print fields.__repr__()
#         f.write(fields.__repr__())
#         f.write("\n")
#     print ''
#     f.write("\n")
#
# print ''
# f.write("\n")
# f.close()
#ITSP = IdaTypeStorage()
#ITSP.storage.clearStorage()
#ITSP.allTypeToStorage()
#ITSP.allTypeFromStorage()
#ITSP.ChooseLocalTypes()
#ITSP.ChooseTypesFromStorage()

# f = ConnectToBase()
# r = f.Go()
# f.Free()
# print r
# if r != None:
# if r != None:
#     client = MongoClient(r[0],int(r[1]))
#     db = client['LocalTypesStorage']
#     coll_names = db.collection_names(include_system_collections = False)
#     f = ChooseProject(coll_names)
#     r1 = f.Go()
#     f.Free()
#     print r1
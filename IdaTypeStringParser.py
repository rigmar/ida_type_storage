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

c_free_til = g_dll.free_til
c_free_til.argtypes = [
    c_void_p
]

c_serialize_tinfo = g_dll.serialize_tinfo
c_serialize_tinfo.argtypes = [
    ctypes.POINTER(qtype),              #qtype *type
    ctypes.POINTER(qtype),              #qtype *fields
    ctypes.POINTER(qtype),              #qtype *fldcmts
    ctypes.POINTER(ctypes.c_ulong),     #const tinfo_t *tif
    ctypes.c_int                        #int sudt_flags
]

c_new_til = g_dll.new_til
c_new_til.argtyped = [
    c_char_p,                           #const char *name
    c_char_p                            #const char *desc
]
c_new_til.restype = c_void_p

c_parse_decl2 = g_dll.parse_decl2
parse_decl2.argtypes = [
    c_void_p,                           #param til          type library to use
    c_char_p,                           #param decl         C declaration to parse
    ctypes.POINTER(qtype),              #param[out] name    declared name
    ctypes.POINTER(ctypes.c_ulong),     #param[out] tif     type info
    ctypes.c_int                        #param flags        combination of \ref PT_
]

c_deserialize_tinfo = g_dll.deserialize_tinfo
c_deserialize_tinfo.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),     #tinfo_t *tif
    ctypes.c_void_p,                    #const til_t *til
    ctypes.POINTER(ctypes.c_char_p),    #const type_t **ptype
    ctypes.POINTER(ctypes.c_char_p),    #const p_list **pfields
    ctypes.POINTER(ctypes.c_char_p)     #const p_list **pfldcmts
]

c_print_tinfo = g_dll.print_tinfo
c_print_tinfo.argtypes = [
    ctypes.POINTER(qtype),              #qstring *result
    ctypes.c_char_p,                    #const char *prefix
    ctypes.c_int,                       #int indent
    ctypes.c_int,                       #int cmtindent
    ctypes.c_int,                       #int flags
    ctypes.POINTER(ctypes.c_ulong),     #const tinfo_t *tif
    ctypes.c_char_p,                    #const char *name
    ctypes.c_char_p                     #const char *cmt
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

LocalTypeMap = {}

def convert_to_string(src):
    ret = ""
    for ch in src:
        if ch == 0:
            break
        ret = ret + struct.pack("B",ch)
    return ret

duplicate_form_text = r"""STARTITEM 0
Duplicate resolver
%s
Detected type duplicate
You must select a variant

Default rule if pressed "OK" or "Cancel":

Import from storage - 'Existing type' from storage will replaced by type in IDA
Export to storage - 'Existing type' from IDA will replaced by type in storage

You can edit structure and use appropriate button to save the edited type

{FormChangeCb}
<%s:{txtMultiLineText}><##Keep exist type:{iButton1}>
<%s:{txtMultiLineText2}><##Replace type:{iButton2}>

"""

class DuplicateResolverForm(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self,fToStorage = False):
        if fToStorage:
            form_str = duplicate_form_text%("Export to storage","Existing type in storage","Local type in IDA for replace")
        else:
            form_str = duplicate_form_text%("Import from storage","Existing local type in IDA","Local type in storage for replace")
        self.selected = ""
        Form.__init__(self, form_str, {
            'txtMultiLineText': Form.MultiLineTextControl(text="",width=100),
            'txtMultiLineText2': Form.MultiLineTextControl(text="",width=100),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
        })

    def Go(self,text1,text2):
        self.Compile()
        self.txtMultiLineText.text = text1
        self.txtMultiLineText2.text = text2
        ok = self.Execute()
        #print "Ok = %d"%ok
        sel = self.selected
        #print sel
        #print len(sel)
        return sel

    def OnFormChange(self, fid):
        #print(">>fid:%d" % fid)
        if fid == self.txtMultiLineText.id:
            pass
        elif fid == -2 or fid == -1:
            self.selected = self.GetControlValue(self.txtMultiLineText).text
            #print "ti.text = %s" % ti.text
        return 1

    def OnButton1(self, code=0):
        #print("Button1 pressed")
        self.selected = self.GetControlValue(self.txtMultiLineText).text
        self.Close(1)


    def OnButton2(self, code=0):
        #print("Button2 pressed")
        self.selected = self.GetControlValue(self.txtMultiLineText2).text
        self.Close(1)


class TypeListChooser(Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, type_list, flags=0):
        Choose2.__init__(self,
                         title,
                         [ ["Num", 5], ["Name", 40] ],
                         embedded=True, width=150, height=40, flags=flags)
        self.n = 0
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selcount = 0
        self.selected = []
        self.make_items(type_list)

    def make_items(self,item_list):
        self.n = 1
        r = []
        for name in item_list:
            r.append([str(self.n), name])
            self.n += 1
        self.items = r
        return r

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnSelectionChange(self, sel_list):
        self.selected = []
        #print sel_list
        for n in sel_list:
            self.selected.append(self.items[n-1][1])
        #print self.selected

class TypeListChooser2(Choose2):

    def __init__(self, title, type_list, flags=Choose2.CH_MULTI):
        Choose2.__init__(
            self,
            title,
            [ ["Num", 5], ["Name", 30] ],
            flags = flags)
        self.n = 0
        self.items = []
        self.icon = 0
        self.selcount = 0
        #self.modal = modal
        self.selected = []
        self.make_items(type_list)

        print("created %s" % str(self))

    def OnClose(self):
        print "closed", str(self)

    # def OnEditLine(self, n):
    #     self.items[n][1] = self.items[n][1] + "*"
    #     print("editing %d" % n)

    # def OnInsertLine(self):
    #     self.items.append(self.make_item())
    #     print("insert line")

    # def OnSelectLine(self, n):
    #     print "selectline"
    #     if n >= 0:
    #         self.selected.append(self.items[n][1])

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    # def OnDeleteLine(self, n):
    #     print("del %d " % n)
    #     del self.items[n]
    #     return n

    def OnRefresh(self, n):
        print("refresh %d" % n)
        return n

    # def OnGetIcon(self, n):
    #     r = self.items[n]
    #     t = self.icon + r[1].count("*")
    #     #print "geticon", n, t
    #     return t

    # def show(self):
    #     return self.Show(self.modal) >= 0

    def make_items(self,item_list):
        self.n = 0
        r = []
        for name in item_list:
            r.append([str(self.n), name])
            self.n += 1
        self.items = r
        return r

    # def OnGetLineAttr(self, n):
    #     #print("getlineattr %d" % n)
    #     if n == 1:
    #         return [0xFF0000, 0]

    # def OnSelectionChange(self, sel_list):
    #     self.selected = []
    #     #print sel_list
    #     for n in sel_list:
    #         self.selected.append(self.items[n-1][1])
    #     #print sel_list


form_text = """%s

<Types for choose:{cEChooser}>
<##Get all types:{iButtonSyncAll}><Resolve type dependencies:{rResDep}>{cGroup1}>
"""
class TypeChooseForm(Form):
    def __init__(self,title_str,type_list):

        self.EChooser = TypeListChooser("aaa",type_list,flags=Choose2.CH_MULTI)
        Form.__init__(self,form_text%title_str, {
                                             'cEChooser' : Form.EmbeddedChooserControl(self.EChooser),
                                             'iButtonSyncAll': Form.ButtonInput(self.onSyncAllTypes),
                                             'cGroup1': Form.ChkGroupControl(("rResDep",))
                                             })





    def Go(self):
        self.Compile()
        self.rResDep.checked = True
        ok = self.Execute()
        print "Ok = %d"%ok
        if ok == 1:
            sel = self.EChooser.selected
            #print sel
            #print len(sel)
            return sel, self.rResDep.checked

    def onSyncAllTypes(self,code=0):
        self.EChooser.selected = []
        for i in self.EChooser.items:
            self.EChooser.selected.append(i[1])
        self.Close(1)


class ProjectChooser(Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, name_list, flags=0):
        Choose2.__init__(self,
                         title,
                         [ ["Project name", 40] ],
                         embedded=True, width=40, height=10, flags=flags)
        self.n = 0
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selcount = 0
        self.selected = []
        self.make_items(name_list)

    def make_items(self,item_list):
        self.n = 1
        r = []
        for name in item_list:
            r.append([name])
            self.n += 1
        self.items = r
        return r

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnSelectLine(self, n):
        #print "Selected %d"%n
        self.selected = self.items[n]

    def OnSelectionChange(self, sel_list):
        self.selected = self.items[sel_list[0]-1]


    # def OnSelectionChange(self, sel_list):
    #     self.selected = []
    #     #print sel_list
    #     for n in sel_list:
    #         self.selected.append(self.items[n-1][1])
    #     #print self.selected


class ChooseProject(Form):
    def __init__(self,coll_list):
        self.__n = 0
        self.EChooser = ProjectChooser("Projects in storage",coll_list)
        Form.__init__(self,
r"""
Choose project for connect

<Projects in storage:{cEChooser}>   <##Create new project:{iButtonNewProject}>
""", {
        'cEChooser' : Form.EmbeddedChooserControl(self.EChooser),
        'iButtonNewProject': Form.ButtonInput(self.onNewProject),
    })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        #print "Ok = %d"%ok
        if ok == 1:
            sel = self.EChooser.selected
            #print sel
            #print len(sel)
            return sel[0]

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def onNewProject(self,code = 0):
        s = idc.AskStr("", "Enter new project name:")
        self.EChooser.selected = [s]
        self.Close(1)



class ConnectToBase(Form):
    def __init__(self):
        self.storage = None
        self.iServerIP = None
        self.iPort = None

        Form.__init__(self,r"""
        Choose server with storage

        <#Hint1#Server IP:{iServerIP}> : <#Hint1#Server port:{iPort}>
        """, {
            'iServerIP':Form.StringInput(value = "127.0.0.1"),
            'iPort':Form.NumericInput(Form.FT_DEC,27017),
        })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        print "ConnectToBase: Go: Ok = %d; ServerIP = %s; Port = %d"%(ok,self.iServerIP.value,self.iPort.value)
        if ok == 1:
            return self.iServerIP.value, self.iPort.value
        return None




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
    (ord_len,) = struct.unpack("B",enc[0])
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

class IdaTypeStringParser:

    def __init__(self):
        self.LocalTypeMap = {}
        self.FreeOrdinals = []
        self.storage = None
        self.addmenu_item_ctxs = []
        self.typesNamesInStorage = []
        self.cachedStorage = {}
        self.fResDep = True

    def ConnectToStorage(self):
        #try:
        f = ConnectToBase()
        r = f.Go()
        f.Free()
        print r
        if r != None:
            serverIP, port = r
            port = int(port)
            try:
                client_try = MongoClient(serverIP,port)
                db = client_try['LocalTypesStorage']
                coll_names = db.collection_names(include_system_collections = False)
                client_try.close()
                f = ChooseProject(coll_names)
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

    def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):

        # add menu item and report on errors
        addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
        if addmenu_item_ctx is None:
            return 1
        else:
            self.addmenu_item_ctxs.append(addmenu_item_ctx)
            return 0

    def add_menu_items(self):
        if self.add_menu_item_helper("File/Take database snapshot...", "Import types from storage", "Shift+i", 0, self.doImportTypes, None): return 1

        if self.add_menu_item_helper("File/Take database snapshot...", "Export types to storage", "Shift+g", 0, self.doExportTypes, None): return 1
        # if self.add_menu_item_helper("Search/all error operands", "ROP gadgets...", "Alt+r", 1, self.show_rop_view, None): return 1
        #
        # if self.add_menu_item_helper("Edit/Begin selection", "Create pattern...", "Shift+c", 0, self.show_pattern_create, None): return 1
        # if self.add_menu_item_helper("Edit/Begin selection", "Detect pattern...", "Shift+d", 0, self.show_pattern_detect, None): return 1
        # if self.add_menu_item_helper("Edit/Begin selection", "Compare file to memory...", "Shift+f", 0, self.show_compare, None): return 1

        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    def doImportTypes(self):
        self.fResDep = True
        pydevd.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return

        sel_list = self.ChooseTypesFromStorage()
        print sel_list
        if sel_list is not None and len(sel_list) > 0:
            fromStorage = self.getFromStorage(sel_list)
            if self.fResDep:
                sorted_list = self.resolveDependencies(fromStorage)
            else:
                sorted_list = fromStorage

            for t in sorted_list:
                self.InsertType(t)
            print "Imported from storage %d types"%len(sorted_list)

    def doExportTypes(self):
        self.fResDep = True
        pydevd.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        if self.storage is None:
            if  not self.ConnectToStorage():
                return
        self.Initialise()
        sel_list = self.ChooseLocalTypes()
        if len(sel_list) > 0:
            if self.fResDep:
                sorted_list = self.resolveDependenciesForExport(sel_list)
            else:
                sorted_list = sel_list
            self.saveToStorage(sorted_list)
            print "Exported to storage %d types"%len(sorted_list)


    def Initialise(self):
        global my_til
        my_ti = idaapi.cvar.idati
        self.LocalTypeMap = {}
        self.FreeOrdinals = []
        for i in range(1, GetMaxLocalType()):
        # for i in range(12114, 12115):
            name = GetLocalTypeName(i)
            print "Ordinal = %d; Type name = %s"%(i,name)
            if name != None:
                typ_type = ctypes.c_char_p()
                typ_fields = ctypes.c_char_p()
                typ_cmt = ctypes.c_char_p()
                typ_fieldcmts = ctypes.c_char_p()
                typ_sclass = ctypes.c_ulong()
                ret = get_numbered_type(
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
                #print typ_type
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
                t = LocalType(name,typ_type,typ_fields,typ_cmt,typ_fieldcmts,typ_sclass)
                self.LocalTypeMap[name] = t
                continue
            self.FreeOrdinals.append(i)
        print len(self.LocalTypeMap)
        # f = open("F:\IdaTextTypesParser\cache.dat","wb")
        # pickle.dump(self.LocalTypeMap,f)
        # f.close()

    def ImportLocalType(self,idx):
        global my_til
        name = GetLocalTypeName(idx)
        if name != None:
            typ_type = ctypes.c_char_p()
            typ_fields = ctypes.c_char_p()
            typ_cmt = ctypes.c_char_p()
            typ_fieldcmts = ctypes.c_char_p()
            typ_sclass = ctypes.c_ulong()
            ret = get_numbered_type(
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
            return LocalType(name,typ_type,typ_fields,typ_cmt,typ_fieldcmts,typ_sclass)
        return None

    def InsertType(self,type_obj):
        global my_ti
        my_ti = idaapi.cvar.idati
        print "InsertType:",type(type_obj.name), type_obj.name
        # print "InsertType: idx = %d"%self.getTypeOrdinal(type_obj.name.encode("ascii"))
        # print "InsertType: idx = %d"%self.get_type_ordinal(my_ti,type_obj.name.encode("ascii"))
        if self.getTypeOrdinal(type_obj.name.encode("ascii")) != 0:
            print "InsertType: getTypeOrdinal"
            idx = self.getTypeOrdinal(type_obj.name.encode("ascii"))
            t = self.ImportLocalType(idx)
            type_obj = self.DuplicateResolver(type_obj,t)
            if t.TypeString == type_obj.TypeString and t.TypeFields == type_obj.TypeFields:
                return 1
        elif len(self.FreeOrdinals) > 0:
            print "InsertType: FreeOrdinals.pop"
            idx = self.FreeOrdinals.pop(0)
        else:
            print "InsertType: alloc_type_ordinals"
            idx = alloc_type_ordinals(my_ti,1)
        print "InsertType: type_obj.parsedList = ", type_obj.parsedList
        print "InsertType: idx = %d"%idx
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
        if type(type_obj.sclass) == int:
            type_obj.sclass = ctypes.c_ulong(type_obj.sclass)
        ret = set_numbered_type(
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
        print "InsertType: ret = %d"%ret
        if ret != 1:
            print "bad"
        return ret


    def getTypeOrdinal(self,name):
        global my_ti
        my_ti = idaapi.cvar.idati
        return get_type_ordinal(my_ti,name)

    def ChooseLocalTypes(self):
        if len(self.LocalTypeMap) == 0:
            self.Initialise()
        f = TypeChooseForm("Import types from current IDB",self.LocalTypeMap)
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
        f = TypeChooseForm("Import types from storage",self.storage.GetAllNames())
        r = f.Go()
        f.Free()
        if r != None and len(r[0]) != 0:
            selected, fResDep = r
            self.fResDep = fResDep
        else:
            selected = ""
        # print selected
        # print len(selected)
        return selected

    def saveToStorage(self,typesList):
        for t in typesList:
            if self.storage.isExist(t.name):
                if not self.storage.checkEquality(t):
                    t1 = self.DuplicateResolver(t, self.getFromStorage([t.name])[0])
                    if not self.storage.checkEquality(t1):
                        self.storage.updateType(t1.name,t1)
                        self.cachedStorage[t1.name] = t1
                        print "Edited type updated"
                    # raise NameError("saveToStorage: Duplicated type name (%s) with differ body"%t.name)
                    else:
                        print "Edited type don't have changes"
                continue
            self.storage.putToStorage(t)
            self.cachedStorage[t.name] = t

    def getFromStorage(self,typesListNames):
        typesList = []
        for name in typesListNames:
            if name in self.cachedStorage:
                typesList.append(self.cachedStorage[name])
                continue
            t = self.storage.getFromStorage(name)
            if t is None:
                raise NameError("getFromStorage: Type name (%s) not in the storage"%name)
            typesList.append(t)
            self.cachedStorage[name] = t
        return typesList

    def resolveDependencies(self,startList):
        toResolve = []
        toResolveNames = []
        print "resolveDependencies: startList", startList
        prev_len = -1
        while len(toResolve) != prev_len:
            if type(startList[0]) == str or type(startList[0]) == unicode:
                startList = self.getFromStorage(startList)
            for t in startList:
                for name in t.depends:
                    if name not in toResolve:
                        toResolve.append(name)
                if t.name not in toResolve:
                    toResolve.append(t.name)
            prev_len = len(toResolve)
            startList = toResolve
        sortedList = []
        print "resolveDependencies: toResolveNames", toResolve
        toResolveNames = toResolve
        toResolve = self.getFromStorage(toResolve)
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
            if name in self.LocalTypeMap:
                type_list.append(self.LocalTypeMap[name])
            else:
                raise NameError("getLocalTypesFromMap: missing type %s"%name)

        return type_list

    def resolveDependenciesForExport(self,startList):
        toResolve = []
        toResolveNames = []
        print "resolveDependenciesForExport: startList", startList
        prev_len = -1
        while len(toResolve) != prev_len:
            prev_len = len(toResolve)
            if type(startList[0]) == str or type(startList[0]) == unicode:
                startList = self.getFromLocalTypesMap(startList)
            for t in startList:
                for name in t.depends:
                    if name not in toResolve:
                        toResolve.append(name)
                if t.name not in toResolve:
                    toResolve.append(t.name)
            startList = toResolve
        sortedList = []
        print "resolveDependenciesForExport: toResolveNames", toResolve
        toResolveNames = toResolve
        toResolve = self.getFromLocalTypesMap(toResolve)
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
                            raise NameError("resolveDependenciesForExport: Unresolved type dependencies %s"%name)
            prev_len = len(toResolve)
        return sortedList


    def addTypeWrapper(self,name):
        global wrapperTypeString
        return LocalType(name,wrapperTypeString)


    def checkExistence(self,name_list,target_list):
        fNeq = 0
        for name in name_list:
            if name in target_list:
                fNeq += 1
        if len(name_list) == fNeq:
            return True
        return False

    def allTypeToStorage(self):
        toStorage = []
        self.Initialise()
        for t in self.LocalTypeMap.values():
            toStorage.append(t)
        self.saveToStorage(toStorage)

    def getAllTypesFromStorage(self):
        names = self.storage.GetAllNames()
        return self.getFromStorage(names)


    def allTypeFromStorage(self):
        fromStorage = self.getAllTypesFromStorage()
        sorted_list = self.resolveDependencies(fromStorage)
        print sorted_list
        for t in sorted_list:
            self.InsertType(t)

    def DuplicateResolver(self,t1,t2):
        tif1 = ctypes.c_ulong()
        tif2 = ctypes.c_ulong()
        text1 = ""
        text2 = ""
        til = c_new_til("temp_til","temp")
        if c_deserialize_tinfo(byref(tif1),til,ctypes.c_char_p(t1.TypeString),ctypes.c_char_p(t1.TypeFields),ctypes.c_char_p(t1.fieldcmts)) == 1 and \
        c_deserialize_tinfo(byref(tif2),til,ctypes.c_char_p(t2.TypeString),ctypes.c_char_p(t2.TypeFields),ctypes.c_char_p(t2.fieldcmts)) == 1:
            ret = qtype()
            ret.cur_size = 0
            ret.max_size = 0
            c_print_tinfo(byref(ret),ctypes.c_char_p(),0,0,idaapi.PRTYPE_MULTI|PRTYPE_TYPE,byref(tif1),ctypes.c_char_p(t1.name),ctypes.c_char_p())
            text1 = ret.ptr
            ret = qtype()
            ret.cur_size = 0
            ret.max_size = 0
            c_print_tinfo(byref(ret),ctypes.c_char_p(),0,0,idaapi.PRTYPE_MULTI|PRTYPE_TYPE,byref(tif2),ctypes.c_char_p(t2.name),ctypes.c_char_p())
            text2 = ret.ptr
            f = DuplicateResolverForm()
            sel = f.Go(text1,text2)
            print sel
            if len(sel) != 0:
                if sel == text1:
                    c_free_til(til)
                    return t1
                elif sel == text2:
                    c_free_til(til)
                    return t2
                else:
                    name = qtype()
                    name.cur_size = 0
                    name.max_size = 0
                    sel = sel.split('\n',1)
                    if sel[-1] != ';':
                        sel = sel + ';'
                    r = idc_parse_decl(til,sel,PT_TYP)
                    if r is not None:
                        name, type_str, fields_str = r
                        return LocalType(name,type_str,fields_str)
                    else:
                        raise NameError("DuplicateResolver: bad parse edited type")
            return None

        else:
            c_free_til(til)
            raise NameError("DuplicateResolver.__init__(): Deserialize error")




class Storage(object):
    def __init__(self,ip = 'localhost',port = 27017 ,target_collection = "main_storage"):
        self.client = MongoClient(ip, port)
        self.db = self.client["LocalTypesStorage"]
        self.collection = self.db[target_collection]
        self.cache ={}

    def putToStorage(self,t):
        self.collection.insert_one(t.to_dict())
        res = self.collection.find({'name':t.name})
        if res.count() == 1:
            self.cache[t.name] = res[0]
        else:
            raise NameError("putToStorage: Putting error. Count = %d. Type %s"%(res.count(),t.name))


    def clearStorage(self):
        self.collection.drop()

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
        if name in self.cache:
            return LocalType().from_dict(self.cache[name])
        res = self.collection.find({"name":name})
        if res.count() == 1:
            self.cache[name] = res[0]
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
            self.cache[name] = t.to_dict()
            return True
        elif ret.matched_count == 0:
            return False
        else:
            raise NameError("updateType: Type duplication or error. Count = %d"%(ret.count()))

    def GetAllNames(self):
        names = []
        if len(self.cache) == 0:
            for t in self.collection.find():
                names.append(t['name'])
                self.cache[t['name']] = t
        else:
            for name in self.cache.keys():
                names.append(name)
        return names

    def GetAllTypes(self):
        names = self.GetAllNames()
        types = []
        for name in names:
            types.append(self.getFromStorage(name))
        return types

class LocalType(object):
    def __init__(self, name = "", TypeString = "", TypeFields = "",cmt = "", fieldcmts = "", sclass = 0, parsedList = [], depends = []):
        self.TypeString = TypeString
        self.TypeFields = TypeFields
        self.cmt = cmt
        self.fieldcmts = fieldcmts
        self.sclass = sclass
        self.name = name
        self.parsedList = []
        self.depends = []

        self.parsedList = self.ParseTypeString(TypeString)

    # def __init__(self, idx):
    #     self.name = None
    #     self.parsedList = []
    #     self.TypeString = None
    #     self.TypeFields = None
    #     self.cmt = None
    #     self.fieldcmts = None
    #     self.sclass = None
    #     self.depends = []


    def find_type_by_name(self, name):
        my_ti = cvar.idati
        ordinal = get_type_ordinal(my_ti,name)

    def GetTypeString(self):
        ti = idaapi.cvar.idati
        print "GetTypeString: name %s"%self.name
        the_bytes = []
        for thing in self.parsedList:
            if type(thing) == int:  # if it's a byte, just put it back in
                the_bytes.append(thing)
            else:
                the_bytes.append(ord("="))  # a type starts with =
                print type(thing["local_type"]),thing["local_type"]
                ordinal = get_type_ordinal(ti,thing["local_type"].encode("ascii"))  # get the ordinal of the Local Type based on its name
                if ordinal > 0:
                    the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
                else:
                    raise NameError("Depends local type not in IDB")
        packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
        return packed

    def ParseTypeString(self,type_string):
        tp = TinfoReader(type_string)
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
            if a_byte == ord("="):  # a type begins
                ordinal_length = tp.read_byte()
                number_marker = tp.read_byte()
                #unwritten_bytes.append(number_marker)
                if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
                    ordinal = decode_ordinal_string(struct.pack("B",ordinal_length) + "#" + tp.read_string(ordinal_length-2))
                    t = GetLocalTypeName(ordinal)
                    output.append({"local_type": t})
                    if t not in self.depends:
                        self.depends.append(t)
                    continue
                unwritten_bytes.append(ordinal_length)
                unwritten_bytes.append(number_marker)

            output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is

        return output

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
        self.sclass = int(ser_dic['sclass'])
        self.parsedList = ser_dic['parsedList']
        self.depends = ser_dic['depends']
        self.sclass = ctypes.c_ulong(self.sclass)
        return self

class IDATypeStorage(plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "Single repository for types."
    help = "Single repository for types."
    wanted_name = "IDA Type Storage"
    wanted_hotkey = ""

    def init(self):

        # Only Intel x86/x86-64 are supported
        print "Enter IDATypeStorage.init()"
        global type_string_parser
        #type_string_parser = None

        # Check if already initialized
        print not 'type_string_parser' in globals()
        if not 'type_string_parser' in globals():

            type_string_parser = IdaTypeStringParser()
            if type_string_parser.add_menu_items():
                print "Failed to initialize IDA Type Storage."
                type_string_parser.del_menu_items()
                del type_string_parser
                return idaapi.PLUGIN_SKIP
            else:
                print"Initialized IDA Type Storage."

        return idaapi.PLUGIN_KEEP


    def run(self, arg):
        pass

    def term(self):
        global type_string_parser
        if type_string_parser in globals() and type_string_parser is not None:
            type_string_parser.storage.Close()
            del type_string_parser

def PLUGIN_ENTRY():
    return IDATypeStorage()

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
#ITSP = IdaTypeStringParser()
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
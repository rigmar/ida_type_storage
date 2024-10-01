import ida_typeinf
import ida_kernwin
import struct
import base64
import collections
import pickle


class LocalType(object):
    
    table_name = "LocalTypes"
    columns_info = [
        ["name", "text"],
        ["TypeString", "text"],
        ["TypeFields", "text"],
        ["cmt", "text"],
        ["dstr", "text"],
        ["fieldcmts", "text"],
        ["sclass", "text"],
        ["parsedList", "text"],
        ["depends", "text"],
        ["depends_ordinals", "text"],
        ["flags", "integer"]
    ]
    dummy_type_string = b'\x0d\x01\x01'
    
    # Flags = {
    #     "struct":1,
    #     "enum":2,
    #     "other":4,
    #     "standard":8
    # }
    
    def __init__(self, name="", TypeString=b"", TypeFields=b"", cmt=b"", fieldcmts=b"", sclass=0, parsedList=None, depends=None, isStandard=False, dstr = ''):
        super().__init__()
        self.TypeString = TypeString
        self.TypeFields = TypeFields
        self.cmt = cmt
        self.fieldcmts = fieldcmts if type(fieldcmts) == bytes else fieldcmts.encode("utf-8")
        self.sclass = sclass
        self.name = name
        self.dstr = dstr
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
    def is_type_exist(name):
        idx = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), name)
        if idx > 0:
            return True
        return False
    
    @staticmethod
    def find_type_by_name(name):
        my_ti = ida_typeinf.cvar.idati
        ordinal = ida_typeinf.get_type_ordinal(my_ti, name)
    
    @property
    def key(self):
        return self.name
    
    def GetTypeString(self):
        ti = ida_typeinf.get_idati()
        # print "GetTypeString: name %s"%self.name
        the_bytes = []
        for thing in self.parsedList:
            if type(thing) == int:  # if it's a byte, just put it back in
                the_bytes.append(thing)
            elif len(thing) == 1:
                # if list(thing.keys())[0] == "local_type":
                #     the_bytes.append(ord("="))  # a type starts with =
                # print type(thing["local_type"]),thing["local_type"]
                ordinal = ida_typeinf.get_type_ordinal(ti, list(thing.values())[0])  # get the ordinal of the Local Type based on its name
                if ordinal > 0:
                    the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
                else:
                    raise NameError("Depends local type not in IDB")
            else:
                raise NameError("Wrong depend record for type: %s!" % self.name)
        packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
        return packed
    
    def ParseTypeString(self, type_string):
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
            if a_byte == ord("=") and tp.pos < len(tp.tp):  # a type begins
                ordinal_length = tp.read_byte()
                if tp.pos < len(tp.tp) and len(tp.tp) - (tp.pos + ordinal_length - 1) >= 0:
                    number_marker = tp.read_byte()
                    if number_marker == ord("#"):  # this is a Local Type referred to by its ordinal
                        ordinal = decode_ordinal_string(struct.pack("B", ordinal_length) + b"#" + tp.read_string(ordinal_length - 2))
                        t = ida_typeinf.get_numbered_type_name(None ,ordinal)
                        output.append(a_byte)
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
            elif a_byte == ord("#") and check_rare_type_condition(output):
                ordinal_length = output[-1]
                if tp.remain_len() >= (ordinal_length - 2):
                    output.pop(-1)
                    ordinal = decode_ordinal_string(struct.pack("B", ordinal_length) + b"#" + tp.read_string(ordinal_length - 2))
                    t = ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), ordinal)
                    output.append({"local_type": t})
                    if t not in self.depends:
                        self.depends.append(t)
                        self.depends_ordinals.append(ordinal)
                continue
            
            output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is
        
        return output
    
    def to_dict(self):
        ser_dic = collections.OrderedDict()
        ser_dic['name'] = self.name
        ser_dic['dstr'] = self.dstr
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
        return self.name, base64.b64encode(self.TypeString), base64.b64encode(self.TypeFields), base64.b64encode(self.cmt), base64.b64encode(
            self.fieldcmts), base64.b64encode(pickle.dumps(self.sclass)), base64.b64encode(pickle.dumps(self.parsedList)), base64.b64encode(
            pickle.dumps(self.depends)), base64.b64encode(pickle.dumps(self.depends_ordinals)), self.flags
    
    def from_dict(self, ser_dic):
        self.name = ser_dic['name']
        self.dstr = ser_dic['dstr']
        self.TypeString = base64.b64decode(ser_dic['TypeString'])
        # print "from_dict; TypeString = %s"%self.TypeString
        self.TypeFields = base64.b64decode(ser_dic['TypeFields'])
        self.cmt = base64.b64decode(ser_dic['cmt'])
        self.fieldcmts = base64.b64decode(ser_dic['fieldcmts'])
        self.sclass = pickle.loads(base64.b64decode(ser_dic['sclass']))
        self.parsedList = pickle.loads(base64.b64decode(ser_dic['parsedList']))
        self.depends = pickle.loads(base64.b64decode(ser_dic['depends']))
        self.depends_ordinals = pickle.loads(base64.b64decode(ser_dic['depends_ordinals']))
        # self.sclass = ctypes.c_ulong(self.sclass)
        self.flags = ser_dic['flags']
        return self
    
    def print_type(self):
        ret = ida_typeinf.idc_print_type(self.GetTypeString(), self.TypeFields, self.name, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE)
        if ret is None:
            return ""
        i = 0
        ret = ret.strip()
        return ret
    
    def is_standard(self):
        return self.flags & 8 == 8
    
    def isEqual(self, t):
        if self.parsedList == t.parsedList \
                and self.TypeFields == t.TypeFields \
                and self.name == t.name:
            return True
        return False
    
    def is_empty(self):
        if self.parsedList is None or len(self.parsedList) == 0:
            return True
        return False
    
    def is_complex(self):
        return self.TypeString[0] & ida_typeinf.TYPE_BASE_MASK == ida_typeinf.BT_COMPLEX
    
    def is_typedef(self):
        return self.TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_TYPEDEF
    
    def is_sue(self):
        return self.is_complex() and not self.is_typedef()
    
    def isnt_sue(self):
        return not self.is_sue()
    
    def is_su(self):
        return self.is_complex() and not self.is_typedef() and not self.is_enum()
    
    def is_paf(self):
        t = self.TypeString[0] & ida_typeinf.TYPE_BASE_MASK
        return (t >= ida_typeinf.BT_PTR) & (t <= ida_typeinf.BT_FUNC)
    
    def is_func(self):
        return self.TypeString[0] & ida_typeinf.TYPE_BASE_MASK == ida_typeinf.BT_FUNC
    
    def is_struct(self):
        return self.TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_STRUCT
    
    def is_union(self):
        return self.TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_UNION
    
    def is_enum(self):
        return self.TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_ENUM
    
    def is_ptr(self):
        return self.TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BT_PTR
    
    @staticmethod
    def is_complex_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_BASE_MASK == ida_typeinf.BT_COMPLEX
    
    @staticmethod
    def is_typedef_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_TYPEDEF
    
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
        t = TypeString[0] & ida_typeinf.TYPE_BASE_MASK
        return (t >= ida_typeinf.BT_PTR) & (t <= ida_typeinf.BT_FUNC)
    
    @staticmethod
    def is_func_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_BASE_MASK == ida_typeinf.BT_FUNC
    
    @staticmethod
    def is_struct_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_STRUCT
    
    @staticmethod
    def is_union_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_UNION
    
    @staticmethod
    def is_enum_static(TypeString):
        return TypeString[0] & ida_typeinf.TYPE_FULL_MASK == ida_typeinf.BTF_ENUM
    
    @staticmethod
    def collect_info(name):
        idx = ida_typeinf.get_type_ordinal(None ,name)
        if idx:
            logger_instance.trace("Collect info for local type %s (%d) " %(name, idx))
            ret = ida_typeinf.get_numbered_type(
                ida_typeinf.get_idati(),
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
            lt =  LocalType(name, typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass)
            lt.dstr = lt.print_type()
            return lt
        return LocalType()
    
    def is_dependencies_resolved(self):
        for depend in self.depends:
            if not self.is_type_exist(depend):
                return False
        return True
    
    def apply_info(self):
        if self.is_dependencies_resolved():
            idx = None
            if ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), self.name) != 0:
                idx = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), self.name)
                t = LocalType.collect_info(self.name)
                if t.isEqual(self) or self.TypeString == self.dummy_type_string:
                    return 1
            
            if idx is None:
                idx = ida_typeinf.alloc_type_ordinal(ida_typeinf.get_idati())
            tif = ida_typeinf.tinfo_t()
            ret = tif.deserialize(ida_typeinf.get_idati() ,self.GetTypeString() ,self.TypeFields ,self.fieldcmts)
            if  not ret:
                ida_kernwin.warning("Error on tinfo deserilization, type name = %s, ret = %d " %(self.name ,ret))
                ret = -1
            else:
                ret = tif.set_numbered_type(ida_typeinf.get_idati() ,idx ,0x4 ,self.name)
            del tif
            return ret
        else:
            ida_kernwin.warning("Can't apply type '%s' because depends not resolved! " %self.name)
            return None
    
    @staticmethod
    def get_processed_item(existed_elem, imported_elem):
        if not existed_elem.is_empty():
            if existed_elem.isEqual(imported_elem):
                merged_type =  'same'
            else:
                merged_type = 'conflict'
        else:
            merged_type = 'new'
        return ProcessedItem(existed_elem, imported_elem ,imported_elem.get_dict_for_merge(imported_elem ,existed_elem ,merged_type) ,merged_type)
    
    @staticmethod
    def get_dict_for_merge(imported_obj, exist_obj, merged_type):
        """

        :type merged_type: str
        :type exist_obj: GlobalVariable
        :type imported_obj: GlobalVariable
        """
        merge_dict = collections.OrderedDict()
        if exist_obj and not exist_obj.is_empty():
            merge_dict["Exist name"] = exist_obj.name
        else:
            merge_dict["Exist name"] = ""
        merge_dict["Imported name"] = imported_obj.name
        merge_dict["Merge type"] = merged_type
        return merge_dict
    
    @staticmethod
    def get_resolver(database_importer, processed_elements):
        return Resolver(database_importer, processed_elements)
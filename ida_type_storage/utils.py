import ida_typeinf



class dependencies_crawler(ida_typeinf.tinfo_visitor_t):
    
    def __init__(self):
        self.dependencies = []
        self.fFirst = True
        super().__init__()
    
    def visit_type(self, *args) -> "int":
        tif: ida_typeinf.tinfo_t
        t_mod, tif, name, cmt = args
        # print("field name = ", name)
        if tif.is_udt() or tif.is_enum() or tif.is_typedef() or tif.is_typeref():
            if tif.get_decltype() & 0xF0 != 0:
                if tif.is_const() or tif.is_volatile():
                    tif.clr_const_volatile()

                # self.state = self.state | ida_typeinf.TVST_DEF
                type_name = tif.get_type_name()
                if type_name and type_name not in self.dependencies:
                    # print("is needed type!")
                    self.dependencies.append(type_name)
        # print("field type = ", tif._print())
        # print("type name = ", tif.get_type_name())
        # print("decltype = 0x%X" % tif.get_decltype())
        # print("realtype = 0x%X" % tif.get_realtype())
        # print("\n")

        return 0


def get_type_dependencies(name, tif):
    # print("Enter to get_type_dependencies. Target type = ", name)
    visitor = dependencies_crawler()
    # tif = ida_typeinf.tinfo_t()
    # tif.get_named_type(ida_typeinf.get_idati(), name)
    # visitor.state |= ida_typeinf.TVST_DEF
    visitor.apply_to(tif)
    type_dependencies = visitor.dependencies
    # print("Type %s dependencies:"%name)
    # print(type_dependencies)
    # print("\n")
    return type_dependencies
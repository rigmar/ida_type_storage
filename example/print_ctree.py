import idautils
import idaapi
from ida_idaapi import *
from ida_hexrays import *
from ida_kernwin import *
import idc
import traceback
import networkx as nx
import matplotlib.image as mpimg
from networkx.drawing.nx_agraph import *

fDebug = False
if fDebug:
    import pydevd

try:
    import matplotlib.pyplot as plt
except:
    raise

print_ctree_actname = "test:print_ctree"

NETNODE_NAME = '$ hexrays-print-ctree'

def hierarchy_pos(G, root, width=1., vert_gap = 0.2, vert_loc = 0, xcenter = 0.5,
                  pos = None, parent = None):
    '''If there is a cycle that is reachable from root, then this will see infinite recursion.
       G: the graph
       root: the root node of current branch
       width: horizontal space allocated for this branch - avoids overlap with other branches
       vert_gap: gap between levels of hierarchy
       vert_loc: vertical location of root
       xcenter: horizontal location of root
       pos: a dict saying where all nodes go if they have been assigned
       parent: parent of this branch.'''
    if pos == None:
        pos = {root:(xcenter,vert_loc)}
    else:
        pos[root] = (xcenter, vert_loc)
    neighbors = G.neighbors(root)
    if parent != None:
        neighbors.remove(parent)
    if len(neighbors)!=0:
        dx = width/len(neighbors)
        nextx = xcenter - width/2 - dx/2
        for neighbor in neighbors:
            nextx += dx
            pos = hierarchy_pos(G,neighbor, width = dx, vert_gap = vert_gap,
                                vert_loc = vert_loc-vert_gap, xcenter=nextx, pos=pos,
                                parent = root)
    return pos

class print_ctree_action_handler_t(idaapi.action_handler_t):
    def __init__(self,obj):
        idaapi.action_handler_t.__init__(self)
        self.hrCbObj = obj

    def activate(self, ctx):
        #print "Activate"
        if fDebug:
            pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True, suspend = False)
        vdui = idaapi.get_tform_vdui(ctx.form)
        vdui.get_current_item(USE_KEYBOARD)
        if vdui.item.is_citem():
            print vdui.item.it.index
        self.hrCbObj.walk_ctree(vdui.cfunc)


        return 1

    def update(self, ctx):
        #print "Update"
        vdui = idaapi.get_tform_vdui(ctx.form)
        if vdui:
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM

class ItemContainer(object):
    def __init__(self,item,parent,item_is_expr,parent_is_expr):
        self.parent = parent
        self.item = item
        self.parent_is_expr = parent_is_expr
        self.item_is_expr = item_is_expr

class hexrays_callback_info(object):

    def __init__(self):
        self.edges = []
        self.vu = None
        self.items = []
        self.G=nx.DiGraph()
        self.cfunc = None


        self.node = idaapi.netnode()
        if not self.node.create(NETNODE_NAME):
            # node exists
            self.load()
        else:
            self.stored = []

        return

    def load(self):

        self.stored = []

        try:
            data = self.node.getblob(0, 'I')
            if data:
                self.stored = eval(data)
                print 'Invert-if: Loaded %s' % (repr(self.stored), )
        except:
            print 'Failed to load invert-if locations'
            traceback.print_exc()
            return

        return

    def save(self):

        try:
            self.node.setblob(repr(self.stored), 0, 'I')
        except:
            print 'Failed to save invert-if locations'
            traceback.print_exc()
            return

        return

    def get_parent_idx(self,target_item):
        for item in self.items:
            if target_item.parent is not None:
                if target_item.parent_is_expr == item.item_is_expr:
                    if item.item == target_item.parent:
                        return self.items.index(item)
            else:
                break
        return None

    def get_item_container(self,item):
        for it in self.items:
            if it.item_is_expr == item.is_expr() and it.item == item:
                return it
        return None

    def get_label(self,n):
        item = self.items[n]
        label = "%d: "%n
        label += idaapi.get_ctype_name(item.op)
        if item.op == idaapi.cot_ptr:
            label += ".%d"%item.cexpr.ptrsize
        elif item.op == idaapi.cot_memptr:
            label += ".%d"%item.cexpr.ptrsize
            label += "m=%d\n"%item.cexpr.m
            label += idaapi.tag_remove(item.cexpr.print1(None))
        elif item.op == idaapi.cot_memref:
            label += "m=%d"%item.cexpr.m
        elif item.op == idaapi.cot_obj or item.op == idaapi.cot_var:
            label += ".%d"%item.cexpr.refwidth
            label += " "
            label += idaapi.tag_remove(item.cexpr.print1(None))
            # print
        elif item.op == idaapi.cot_num or item.op == idaapi.cot_helper or item.op == idaapi.cot_str:
            label += " "
            label += idaapi.tag_remove(item.cexpr.print1(None))
        elif item.op == idaapi.cit_goto:
            label += "LABEL_%d"%item.cinsn.cgoto.label_num
        elif item.op == idaapi.cit_asm:
            label += "%s"%item.cinsn.casm.__repr__()

        label += "\nea: 0x%08X"%item.ea
        if item.is_expr() and not item.cexpr.type.empty():
            label += "\n"
            #print item.cexpr.type._print()
            prefix = ""
            indent = 0
            cmtindent = 0
            flags = idaapi.PRTYPE_1LINE
            name = ""
            cmt = ""
            idaapi.print_tinfo(prefix,indent,cmtindent,flags,item.cexpr.type,name,cmt)
            #print prefix,indent,cmtindent,name,cmt
            label += "%s"%item.cexpr.type
        return label

    def walk_ctree(self, cfunc):
        self.items = []
        self.cfunc = cfunc
        self.G.clear()
        #if fDebug:
        #    pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        print "walk_ctree"
        root = None

        class visitor(idaapi.ctree_visitor_t):

            def __init__(self,obj, cfunc):
                idaapi.ctree_visitor_t.__init__(self,idaapi.CV_PARENTS)
                self.cfunc = cfunc
                self.obj = obj

                return

            def visit_insn(self, i):
                #print "\nvisit_insn"
                #print "item:"
                #print i,'\n'
                parent = None
                #print "Parents:\n",self.parents
                #print "Items:\n",self.obj.items
                if len(self.parents) > 1:

                    parent = self.parents[len(self.parents)-1]
                    # f = self.obj.cfunc.body.find_parent_of(i)
                    #parent =
                    #print parent.cinsn
                    #print parent in self.obj.items
                if parent is not None:
                    self.obj.edges.append((parent.index, i.index))
                self.obj.items.append(i)
                self.obj.G.add_node(i.index)
                return 0 # continue enumeration
            def visit_expr(self, i):
                #print "\nvisit_expr"
                #print "item:"
                #print i,'\n'
                parent = None
                #self.obj.items.append(i)
                #self.obj.G.add_node(self.obj.items.index(i))
                #print "Parents:\n",self.parents
                #print "Items:\n",self.obj.items
                if len(self.parents) > 1:
                    parent = self.parents[len(self.parents)-1]
                    # f = self.obj.cfunc.body.find_parent_of(i)
                    # parent = i.find_parent_of(i)
                    #print parent.cinsn
                if parent is not None:
                    self.obj.edges.append((parent.index, i.index))
                self.obj.items.append(i)
                self.obj.G.add_node(i.index)
                return 0

        visitor(self,cfunc).apply_to(cfunc.body, None)
        #print len(self.items)
        root = None
        # for item in self.items:
        #     #print item.item.opname
        #     #print dir(self)
        #     p = self.get_parent_idx(item)
        #     if p is None:
        #         assert root is None
        #         root = item
        #     else:
        #         self.G.add_edge(p,self.items.index(item))
        for ed in self.edges:
            self.G.add_edge(*ed)
        #pos = hierarchy_pos(self.G,self.items.index(root))
        #nx.draw(self.G,pos,node_shape="s")
        #plt.show() # display
        for u,v,d in self.G.edges(data=True):
            a = self.items[u]
            b = self.items[v]
            if a.is_expr():
                if type(a.x) == type(b) and a.x == b: d["label"] = "x"
                if type(a.y) == type(b) and a.y == b: d["label"] = "y"
                if type(a.z) == type(b) and a.z == b: d["label"] = "z"
        labels = {}
        for j in range(len(self.items)):
            labels[j] = self.get_label(j)
        #print labels
        nx.relabel_nodes(self.G,labels,copy=False)
        A = to_agraph(self.G)
        A.layout('dot')
        # A.draw('graph_test.ps')
        A.draw('graph_test.png')
        # image = mpimg.imread('graph_test.png')
        # plt.axis("off")
        # plt.imshow(image)
        # plt.show()




        return

    def event_callback(self, event, *args):
        #print "event_callback"
        if event == idaapi.hxe_populating_popup:
            #print "event_callback: hxe_populating_popup"
            form, phandle, vu = args
            res = idaapi.attach_action_to_popup(vu.ct, None, print_ctree_actname)

        elif event == idaapi.hxe_maturity:
            #print "event_callback: hxe_maturity"
            cfunc, maturity = args
            #if maturity == idaapi.CMAT_FINAL:
                #print "event_callback: hxe_maturity: CMAT_FINAL"
                #self.walk_ctree(cfunc)

        return 0


class print_ctree_plugin_t(plugin_t):
    flags = PLUGIN_HIDE
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "cobject_helper"
    #wanted_hotkey = "Alt-F8"
    wanted_hotkey = ""

    def init(self):
        #msg("StructTyper init() called!\n")
        if fDebug:
            pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True, suspend= False)
        ret = idaapi.init_hexrays_plugin()
        # print ret
        if not idaapi.init_hexrays_plugin():
            ret = idaapi.load_plugin("hexrays")
            # print ret
            ret = idaapi.init_hexrays_plugin()
            # print ret
        if idaapi.init_hexrays_plugin():
            i = hexrays_callback_info()
            idaapi.register_action(
                idaapi.action_desc_t(
                    print_ctree_actname,
                    "Print HexRays ctree",
                    print_ctree_action_handler_t(i),
                    ""))
            idaapi.install_hexrays_callback(i.event_callback)
            return PLUGIN_KEEP
        else:
            print 'print_ctree: hexrays is not available.'
            return PLUGIN_SKIP

    def run(self, arg):
        #msg("StructTyper run() called with %d!\n" % arg)
        #require('flare')
        #require('flare.struct_typer')
        #struct_typer.main()
        pass


    def term(self):
        #idaapi.msg("StructTyper term() called!\n")
        pass

def PLUGIN_ENTRY():
    return print_ctree_plugin_t()




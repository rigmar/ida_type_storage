str = '''struct __cppobj CList<unsigned int,unsigned int> : CObject
{
  CList<unsigned int,unsigned int>::CNode *m_pNodeHead;
  CList<unsigned int,unsigned int>::CNode *m_pNodeTail;
  int m_nCount;
  CList<unsigned int,unsigned int>::CNode *m_pNodeFree;
  CPlex *m_pBlocks;
  int m_nBlockSize;
};'''
specials = ["__cppobj", "__unaligned", "__declspec"]
def CheckSpecial(data):
        for special in specials:
            if data.startswith(special):
                return True
        return False

def ExtractSpecs(data):
    specs = ()
    while CheckSpecial(data):
        temp = data.strip(" \n;").split(" ",1)
        specs = specs + (temp[0].strip(" \n;"),)
        data = temp[1].strip(" \n;")
    return specs, data




class AA(object):
    def __init__(self):
        self.l = [1,2,3,4,5,6,7,8]
        self.g = []

    def GetL(self):
        return self.l

    def PutToG(self,l,f):
        self.g.append(l*f)

    def Do(self):
        print map(lambda x:self.PutToG(x,10),self.GetL())
        print self.g


def test(func):
    print func
    func()

test(AA().Do)

exit(0)

import re
str2 = '''ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >'''
#str2 = '''CMap<ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *,ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *>::CPair'''
str2 = '''CMap<ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *,ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *>::CAssoc : CMap<ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *,ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *>::CPair'''
#str2 = '''__unaligned __declspec(align(1)) CMapPtrToPtr *m_siteMap;'''

def getline():
    global str
    if str == "":
        return ""
    ret = str.split('\n',1)
    if len(ret) == 1:
        str = ""
        return ret[0]
    str = ret[1]
    return ret[0]

#print str.lower().startswith("struct")
#ret = str.split('\n',1)
#str = ret[1]
#print str.split('{\n',1)[1].split('\n}',1)[0].split('\n')
# while getline() != "":
    # print "ok"

p = re.compile(r'\w*(<.*>)\w*')
tok =  p.findall(str2)
print tok
print tok[0].strip("<>").rstrip("<>")

def SplitSTL(Stl_str):
    ch_op = 0
    ch_cl = 0
    start_pos = 0
    end_pos = 0
    fin = []
    i = 0
    for ch in Stl_str:
        if ch == "<":
            if ch_op == 0:
                start_pos = i
            ch_op += 1
        elif ch == ">":
            ch_cl += 1
        if ch_op == ch_cl and ch_op != 0:
            end_pos = i
            print Stl_str[start_pos:end_pos]
        i += 1

#for name in type_names:

# SplitSTL(tok[0].strip("<>").rstrip("<>"))

# while len(tok):
#     print tok
#     tok = p.findall(tok[0].strip("<>").rstrip("<>"))
# print tok
# print p.findall(tok[0].strip("<>"))
# print tok[0][1:tok[0].find(",")]
# str2 = str2.replace(tok[0],"")
# print str2
# tok =  p.findall(str2)
# print tok
f = '''struct
{
 unsigned __int16 e_magic;
 unsigned __int16 e_cblp;
 unsigned __int16 e_cp;
 unsigned __int16 e_crlc;
 unsigned __int16 e_cparhdr;
 unsigned __int16 e_minalloc;
 unsigned __int16 e_maxalloc;
 unsigned __int16 e_ss;
 unsigned __int16 e_sp;
 unsigned __int16 e_csum;
 unsigned __int16 e_ip;
 unsigned __int16 e_cs;
 unsigned __int16 e_lfarlc;
 unsigned __int16 e_ovno;
 unsigned __int16 e_res[4];
 unsigned __int16 e_oemid;
 unsigned __int16 e_oeminfo;
 unsigned __int16 e_res2[10];
 int e_lfanew;
}'''
# p = re.compile(r'\w*(<.*>)\w*')
# tok =  p.findall(str2)
# print tok
# while len(tok) > 0:



# r =  f.split("\n",1)
# f = r[0] + " " + name + "\n" + r[1]
# print f
#print ExtractSpecs(str2)

# class TypeStructureMember(object):
#     def __init__(self,name,type_name,funcFlag = False,specs = ()):
#         self.name = name
#         self.type_name = type_name
#         self.funcFlag = funcFlag
#         self.specs = specs
#         self.depended = -1
#
#
# a = [TypeStructureMember("1","11"),TypeStructureMember("2","22")]
# b = {}
# for elem in a:
#     b[elem.name] = elem
#
# for elem in b:
#     b[elem].type_name = b[elem].type_name +"AAA"
#
# for elem in a:
#     print elem.type_name

# str2 = '''CMap<ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > >,wchar_t const *,CDocument *,CDocument *>::CPair, IClassFactory, ATL::CComObjectRootEx<ATL::CComMultiThreadModel>'''
# def ParseSuffix(data):
#     i = 0
#     idx = 0
#     while True:
#         if data.find("<") != -1:
#             i = i + 1
#             idx = idx + data.find("<")+1
#             data = data[data.find("<")+1:]
#             continue
#         if data.find(">") != -1:
#             i = i - 1
#             idx = idx + data.find(">")+1
#             data = data[data.find(">")+1:]
#             if i == 0: break
#
# print str2.split(", ")
# ParseSuffix(str2)
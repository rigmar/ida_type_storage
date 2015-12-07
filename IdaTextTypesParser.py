import sys
import re
import pickle


callingConv = ("__stdcall","__cdecl", "__thiscall", "__fastcall" )
base_type = ""
BaseTypes = ("bool","_BYTE","wchar_t","float","const int", "const wchar_t","unsigned __int64","unsigned __int32","unsigned __int16","unsigned __int8","unsigned int","const float","const double","const unsigned __int64","const unsigned __int32","const unsigned __int16","const unsigned __int8", "const unsigned int","__int64","__int32","__int16","__int8","char","const char","void","const void","int","DWORD","volatile unsigned __int64","volatile unsigned __int32","volatile unsigned __int16","volatile unsigned __int8","volatile unsigned int","volatile const float","volatile const double","volatile const unsigned __int64","volatile const unsigned __int32","volatile const unsigned __int16","volatile const unsigned __int8","volatile __int64","volatile __int32","volatile __int16","volatile __int8","volatile char","volatile const char","volatile void","volatile const void","volatile int","volatile DWORD")
str_test = '''struct __cppobj __unaligned __declspec(align(4)) CMFCToolBarImages : CObject
{
  int m_iCount;
  int m_nBitsPerPixel;
  int m_nGrayImageLuminancePercentage;
  int m_nLightPercentage;
  int m_bUserImagesList;
  int m_bModified;
  int m_bStretch;
  int m_bReadOnly;
  int m_bIsTemporary;
  int m_bFadeInactive;
  int m_bIsGray;
  int m_bMapTo3DColors;
  int m_bAlwaysLight;
  int m_bAutoCheckPremlt;
  int m_bCreateMonoDC;
  CDC m_dcMem;
  CSize m_sizeImage;
  CSize m_sizeImageOriginal;
  CSize m_sizeImageDest;
  CRect m_rectLastDraw;
  CRect m_rectSubImage;
  HBITMAP__ *m_hbmImageWell;
  HBITMAP__ *m_hbmImageLight;
  HBITMAP__ *m_hbmImageShadow;
  ATL::CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t> > > m_strUDLPath;
  CBitmap m_bmpMem;
  CBitmap *m_pBmpOriginal;
  unsigned int m_clrTransparent;
  unsigned int m_clrTransparentOriginal;
  unsigned int m_clrImageShadow;
  long double m_dblScale;
  CList<unsigned int,unsigned int> m_lstOrigResIds;
  CList<HINSTANCE__ *,HINSTANCE__ *> m_lstOrigResInstances;
  CMap<unsigned int,unsigned int,int,int> m_mapOrigResOffsets;
};


struct tagHH_AKLINK
{
  int cbStruct;
  int fReserved;
  const wchar_t *pszKeywords;
  const wchar_t *pszUrl;
  const wchar_t *pszMsgText;
  const wchar_t *pszMsgTitle;
  const wchar_t *pszWindow;
  int fIndexOnFail;
};
'''
specials = ["__cppobj", "__unaligned", "__declspec"]
    

from PySide.QtCore import *
from PySide.QtGui import *
import sys
from PySide import QtCore, QtGui


def CheckSpecial(data):
    for special in specials:
        if data.startswith(special):
            return True
    return False

def checkBaseTypes(data):
    global BaseTypes
    global base_type
    for base_type in BaseTypes:
        if data.startswith(base_type+" "):
            return True
    return False

def checkCalling(data):
    global callingConv
    for calling in callingConv:
        if data.find(" " + calling) != -1:
            return data.find(" " + calling)
        elif data.find(" *" + calling) != -1:
            return data.find(" *" + calling)
    return -1

class Ui_Dialog_DuplicateResolveView(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(1088, 844)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(910, 810, 171, 31))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.textEdit_struc1 = QtGui.QTextEdit(Dialog)
        self.textEdit_struc1.setGeometry(QtCore.QRect(10, 60, 501, 361))
        self.textEdit_struc1.setObjectName("textEdit_struc1")
        self.textEdit_struc2 = QtGui.QTextEdit(Dialog)
        self.textEdit_struc2.setGeometry(QtCore.QRect(580, 60, 501, 361))
        self.textEdit_struc2.setObjectName("textEdit_struc2")
        self.textEdit_struc3 = QtGui.QTextEdit(Dialog)
        self.textEdit_struc3.setGeometry(QtCore.QRect(270, 470, 531, 361))
        self.textEdit_struc3.setObjectName("textEdit_struc3")
        self.label_struc1 = QtGui.QLabel(Dialog)
        self.label_struc1.setGeometry(QtCore.QRect(200, 20, 61, 20))
        self.label_struc1.setObjectName("label_struc1")
        self.label_struc2 = QtGui.QLabel(Dialog)
        self.label_struc2.setGeometry(QtCore.QRect(780, 20, 61, 20))
        self.label_struc2.setObjectName("label_struc2")
        self.label_strucMerged = QtGui.QLabel(Dialog)
        self.label_strucMerged.setGeometry(QtCore.QRect(510, 440, 91, 20))
        self.label_strucMerged.setObjectName("label_strucMerged")
        self.pushButton_importStruc1 = QtGui.QPushButton(Dialog)
        self.pushButton_importStruc1.setGeometry(QtCore.QRect(310, 430, 101, 23))
        self.pushButton_importStruc1.setObjectName("pushButton_importStruc1")
        self.pushButton_importStruc2 = QtGui.QPushButton(Dialog)
        self.pushButton_importStruc2.setGeometry(QtCore.QRect(660, 430, 101, 23))
        self.pushButton_importStruc2.setObjectName("pushButton_importStruc2")
        self.pushButton_useMerged = QtGui.QPushButton(Dialog)
        self.pushButton_useMerged.setGeometry(QtCore.QRect(830, 640, 121, 23))
        self.pushButton_useMerged.setObjectName("pushButton_useMerged")

        self.retranslateUi(Dialog)
        #QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        #QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label_struc1.setText(QtGui.QApplication.translate("Dialog", "Structure 1", None, QtGui.QApplication.UnicodeUTF8))
        self.label_struc2.setText(QtGui.QApplication.translate("Dialog", "Structure 2", None, QtGui.QApplication.UnicodeUTF8))
        self.label_strucMerged.setText(QtGui.QApplication.translate("Dialog", "Merged structure", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_importStruc1.setText(QtGui.QApplication.translate("Dialog", "Import struture 1", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_importStruc2.setText(QtGui.QApplication.translate("Dialog", "Import struture 2", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_useMerged.setText(QtGui.QApplication.translate("Dialog", "Use merged structure", None, QtGui.QApplication.UnicodeUTF8))

class DuplicateResolver(QDialog):
    def __init__(self,ITT, parent=None):
        super(DuplicateResolver, self).__init__(parent)
        self.ui = Ui_Dialog_DuplicateResolveView()
        self.ui.setupUi(self)
        self.ITT = ITT
        self.structure_dict = []
        self.struc1_old = None
        self.struc2_old = None
        self.mergedStruc = None
        self.connect(self.ui.pushButton_importStruc1, SIGNAL("clicked()"), self.ImportStruc1)
        self.connect(self.ui.pushButton_importStruc2, SIGNAL("clicked()"), self.ImportStruc2)
        self.connect(self.ui.pushButton_useMerged, SIGNAL("clicked()"), self.pressedUseMerge)
        self.connect(self.ui.pushButton_useMerged, SIGNAL("clicked()"), self.accept)
        #self.ui.textEdit_struc1.setText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.connect(self.ui.buttonBox,SIGNAL("accepted()"),self.pressedOK)
        #self.connect(self.ui.buttonBox,SIGNAL("rejected()"),self.testOK)
        self.connect(self.ui.buttonBox,SIGNAL("accepted()"),self.accept)
        self.connect(self.ui.buttonBox,SIGNAL("rejected()"),self.reject)
        self.notResolved = []
        self.Resolved = []
        self.merged = []
        self.TypesOrdinals = {}


    def ImportStruc1(self):
        struc = self.ui.textEdit_struc1.toPlainText()
        self.ui.textEdit_struc3.setText(struc)

    def ImportStruc2(self):
        struc = self.ui.textEdit_struc2.toPlainText()
        self.ui.textEdit_struc3.setText(struc)

    def pressedOK(self):
        merged = self.ui.textEdit_struc3.toPlainText()
        if merged != "":
            self.pressedUseMerge()
        else:
            struc1 = TypeStructure("",self.ui.textEdit_struc1.toPlainText())
            struc2 = TypeStructure("",self.ui.textEdit_struc2.toPlainText())
            struc1.id = self.struc1_old.id
            struc2.id = self.struc2_old.id
            #self.structure_dict.remove(self.struc2_old)
            if struc1.name == struc2.name:
                self.notResolved.append(struc1)
                self.notResolved.append(struc2)

            else:
                if str(struc2) != str(self.struc2_old):
                    if struc2.name != self.struc2_old.name:
                        self.Resolved.append((self.struc2_old,struc2))
                    self.structure_dict.remove(self.struc2_old)
                    self.structure_dict.append(struc2)
                if struc1.name != self.struc1_old.name:
                    self.Resolved.append((self.struc1_old,struc1))
                self.structure_dict.append(struc1)



    def pressedUseMerge(self):
        merged = self.ui.textEdit_struc3.toPlainText()
        print "pressedUseMerge. Merged:\n%s"%merged
        if merged != "":
            merged = TypeStructure("",merged)
            self.structure_dict.remove(self.struc2_old)
            #del(self.structure_dict[self.struc1_old.name])
            merged.id = self.struc2_old.id
            self.structure_dict.append(merged)
            self.merged.append((self.struc1_old.id,self.struc2_old.name,merged))

    def FixDependsNames(self):
        # for name in self.structure_dict:
        #     #self.structures.append(struc)
        #     self.TypesOrdinals[self.structure_dict[name].id] = self.structure_dict[name]
        for old,new in self.Resolved:
            for struc in self.structure_dict:
                for member in struc.members:
                    if member.funcFlag:
                        member.name =  member.name.replace(old.name,new.name)
                        if struc.struc_type == "typedef":
                            struc.fullName = struc.fullName.replace(old.name,new.name)
                            struc.name = struc.name.replace(old.name,new.name)
                if struc.BaseClasses != None and old.id in struc.BaseClassesDepends:
                    idx = struc.BaseClassesDepends.index(old.id)
                    if struc.BaseClasses[idx] == old.name:
                        struc.BaseClasses[idx] = new.name
                if old.id in struc.membersDepends:
                    if struc.struc_type == "typedef":
                        if struc.type_name == old.name:
                            struc.type_name = new.name
                        if struc.funcFlag:
                            struc.fullName = struc.fullName.replace(old.name,new.name)
                            struc.name = struc.name.replace(old.name,new.name)
                    for member in struc.members:
                        if member.type_name == old.name:
                            member.type_name = new.name
                        if member.funcFlag:
                            member.name =  member.name.replace(old.name,new.name)
        for old_id,old_name,merged in self.merged:
            for struc in self.structure_dict:
                for member in struc.members:
                    if member.funcFlag:
                        member.name =  member.name.replace(old_name,merged.name)
                        if struc.struc_type == "typedef":
                            struc.fullName = struc.fullName.replace(old_name,merged.name)
                            struc.name = struc.name.replace(old_name,merged.name)
                if struc.BaseClasses != None and old_id in struc.BaseClassesDepends:
                    idx = struc.BaseClassesDepends.index(old_id)
                    if struc.BaseClasses[idx] == old_name:
                        struc.BaseClasses[idx] = merged.name
                        struc.BaseClassesDepends[idx] = merged.id
                if struc.BaseClasses != None and merged.id in struc.BaseClassesDepends:
                    idx = struc.BaseClassesDepends.index(merged.id)
                    if struc.BaseClasses[idx] == old_name:
                        struc.BaseClasses[idx] = merged.name
                if old_id in struc.membersDepends:
                    if struc.struc_type == "typedef":
                        struc.fullName = struc.fullName.replace(old_name,merged.name)
                        struc.name = struc.name.replace(old_name,merged.name)
                        struc.type_name = merged.name
                    ind = struc.membersDepends.index(old_id)
                    struc.membersDepends.pop(ind)
                    struc.membersDepends.insert(ind,merged.id)
                    member = struc.members[ind]
                    member.type_name = member.type_name.replace(old_name, merged.name)
                    if member.funcFlag:
                        member.name =  member.name.replace(old_name,merged.name)
                if merged.id in struc.membersDepends:
                    if struc.struc_type == "typedef":
                        struc.fullName = struc.fullName.replace(old_name,merged.name)
                        struc.name = struc.name.replace(old_name,merged.name)
                        struc.type_name = merged.name
                    ind = struc.membersDepends.index(merged.id )
                    member = struc.members[ind]
                    member.type_name = member.type_name.replace(old_name, merged.name)
                    if member.funcFlag:
                        member.name =  member.name.replace(old_name,merged.name)


    def CheckDoubleName(self,name):
        for elem in self.structure_dict:
            if elem.name == name:
                return True
        return False

    def GetStructByName(self,name):
        for elem in self.structure_dict:
            if elem.name == name:
                return elem
        return None


    def Resolve(self):
        global app
        self.structure_dict = []
        self.notResolved = []
        self.Resolved = []
        self.merged = []
        self.TypesOrdinals = {}
        i = 0
        for struc in self.ITT.structures:
            #i = i + 1
            if not self.CheckDoubleName(struc.name):
                self.structure_dict.append(struc)
            else:


                print "Duplicated structure: %s (%d)"%(struc.name,struc.id)
                print struc
                struc_double = self.GetStructByName(struc.name)
                print "Dublicated: %s (%d)"%(struc_double.name,struc_double.id)
                print struc_double

                if struc.__str__().strip() == struc_double.__str__().strip():
                    self.merged.append((struc.id,struc_double.name,struc_double))
                    print "Silent decision - Merge. Merged to id = %d"%struc_double.id
                    continue
                self.ui.textEdit_struc1.setText(str(struc))
                self.struc1_old = struc
                self.ui.textEdit_struc2.setText(str(struc_double))
                self.struc2_old = struc_double
                #self.ITT.app = QApplication(sys.argv)
                self.show()
                app.exec_()
                self.ui.textEdit_struc1.clear()
                self.ui.textEdit_struc2.clear()
                self.ui.textEdit_struc3.clear()

                i = i + 1
                #if i > 5 : break
        self.FixDependsNames()
        return self.structure_dict


    def testOK(self):
        print "Ok"
        print self.ui.textEdit_struc1.toPlainText()



class TypeStructureMember(object):
    def __init__(self,name,type_name,funcFlag = False,specs = ()):
        self.name = name
        self.type_name = type_name
        self.funcFlag = funcFlag
        self.specs = specs
        self.depended = -1

def CheckFunkMember(data):
    if data.rfind(")") != -1:
        if data.find(" (") != -1:
            return  data[:data.find(" (")]
        elif data.find(" *(") != -1:
            return  data[:data.find(" *(")]
    return False

class TypeDef(object):
    def __init__(self,data):
        global base_type
        self.data = data.split("typedef ")[1].strip(" ;\n")
        self.struc_type = "typedef"
        self.fullName = ""
        self.funcFlag = False
        self.id = 0
        self.BaseClasses = None
        self.BaseClassesDepends = []
        self.membersDepends = []
        func = CheckFunkMember(self.data)
        calling = checkCalling(self.data)
        if calling != -1:
            self.type_name = self.data[:calling].strip(" ;\n")
            self.fullName = self.data[calling:].strip(" ;\n")
            self.name = self.fullName[self.fullName.find(" "):self.fullName.find("(")].strip(" ;\n")
        elif checkBaseTypes(self.data) and not func:
            self.type_name = base_type
            self.fullName = self.data.split(base_type + " ",1)[1].strip(" ;\n")
            temp = self.fullName.rsplit(" ",1)
            if len(temp)>1:
                self.name = temp[1].strip(" ;\n")
            else:
                self.name = temp[0].strip(" ;\n")
        elif func:
            self.type_name = func.strip(" ;\n")
            self.fullName = self.data.split(func,1)[1].strip(" ;\n")
            temp = self.fullName[self.fullName.find("(")+1:self.fullName.find(")")]
            temp = temp.rsplit(" ",1)
            if len(temp) > 1:
                self.name = temp[1].strip(" ;\n")
            else:
                self.name = temp[0].strip(" ;\n")
            self.funcFlag = True
        else:
            self.type_name, self.fullName = self.data.rsplit(" ",1)
            self.name = self.fullName
        if self.name.startswith("*"):
            self.ptrFlag = True
            self.name = self.name.strip("*")
        else:
            self.ptrFlag = False
        if self.type_name.startswith("struct "):
            self.type_name = self.type_name[len("struct "):].strip(" ;\n")
        self.members = [TypeStructureMember("",self.type_name)]

    def __str__(self):
        return "typedef %s %s;"%(self.type_name, self.fullName)


class TypeStructure(object):
    def __init__(self,name,data,specs = (),suffix = None, struc_type = "struct"):
        self.specs = specs
        self.BaseClasses = self.ParseBaseClasess(suffix)
        self.id = 0
        self.membersDepends = []
        self.struc_type = struc_type
        self.BaseClassesDepends = []
        if name != "":
            self.name = name
        else:
            self.tempdata = data
            data = self.Parse()
        if self.BaseClasses != None and len(self.BaseClasses) > 1:
            self.needBaseConvert = True
        else:
            self.needBaseConvert = False
        self.members = []
        data = data.strip('\n ;').rstrip('\n ;')
        print "Struct type: %s"%self.struc_type
        print "Data:"
        #print data
        self.CreateMembers(data)
        if self.needBaseConvert:
            self.ConvertBaseClass()
        print "--------------------------------------------------------------\n"

    def ParseBaseClasess(self,data):
        if data != None:
            data = data.strip(": \n;")
            temp = data.split(", ")
            return temp
        else:
            return None


    def CheckFunkMember(self,data):
        if data.rfind(")") != -1:
            if data.find(" (") != -1:
                return  data[:data.find(" (")]
            elif data.find(" *(") != -1:
                return  data[:data.find(" *(")]
        return False

    def getline(self):
        if self.tempdata == "":
            return None

        ret = self.tempdata.split('\n',1)
        #print ret
        if len(ret) > 1:
            self.tempdata = ret[1]
        else:
            self.tempdata = ""
        return ret[0]

    def CheckSpecial(self,data):
        for special in specials:
            if data.startswith(special):
                return True
        return False

    def GetMembers(self):
        #members = self.data.split('{\n',1)[1].split('\n}',1)
        members = self.tempdata[self.tempdata.find("{")+1:self.tempdata.find("}")]
        #print members
        self.tempdata = self.tempdata[self.tempdata.find("}"):]
        return members

    def Parse(self):
        line = self.getline()

        while line != None:
            #print line
            if line.lower().startswith("struct") or line.lower().startswith("const struct") or line.lower().startswith("union"):
                if line.lower().startswith("union"):
                    self.struc_type = "union"
                else:
                    self.struc_type = "struct"
                specs = ()
                body = line.split(" ",1)
                if line.lower().startswith("const struct"):
                    body = body[1]
                    body = body.split(" ",1)
                if len(body) > 1:
                    body = body[1]
                    spec_new = [body]
                    spec = spec_new
                    #print spec
                    while self.CheckSpecial(body):
                        spec_new = body.split(" ",1)
                        if self.CheckSpecial(spec_new[0]):
                            specs = specs + (spec_new[0],)
                            spec = spec_new
                            body = spec_new[1]
                        else:
                            break
                        #print spec
                        #print spec[0].startswith("__")
                        #spec_new = spec[1].split(" ",1)
                    #print spec
                    #print self.specs
                    if self.CheckSpecial(spec[0]):
                           spec.pop(0)
                    if spec[0].find(" : ") != -1:
                            spec = spec[0].rsplit(" : ",1)
                            spec.insert(1,": "+spec[1])
                            spec.pop()
                    if len(spec) > 1:
                        name = spec[0]
                        suffix = spec[1]
                    else:
                        name = spec[0]
                        suffix = None
                    members = self.GetMembers()
                    print "Name = %s"%name
                    #print "Members:\n"
                    #print members
                    #struc = TypeStructure(name,members,specs,suffix)
                    self.name = name
                    self.specs = specs
                    self.BaseClasses = self.ParseBaseClasess(suffix)
                    return members
            line = self.getline()
        
    def checkBaseTypes(self,data):
        global BaseTypes
        global base_type
        for base_type in BaseTypes:
            if data.startswith(base_type):
                return True
        return False

    def CreateMembers(self,data):
        global base_type
        if data == "":
            return
        data = data.split('\n')
        specs = ()
        for member in data:
            member = member.strip('\n ;').rstrip('\n ;')
            if member.startswith("struct "):
                member = member[len("struct "):]
            #print member
            if CheckSpecial(member):
                specs,member = ExtractSpecs(member)
            func = self.CheckFunkMember(member)
            memberPrefix = CheckMemberPrefix(member)
            if memberPrefix != -1 and func == False and not self.checkBaseTypes(member):
                type_name = member[:memberPrefix].split(" ")[0]
                name = member.split(type_name)[1].strip('\n ;').rstrip('\n ;')
                funcFlag = False
            elif self.checkBaseTypes(member) and func == False:
                name = member.split(base_type)[1]
                type_name = base_type
                funcFlag = False
                base_type = ""
            elif func:
                func = func.strip("*")
                name = member.split(func)[1]
                name = name.replace("~","dtor")
                type_name = func.strip('\n ;').rstrip('\n ;')
                funcFlag = True

            else:
                type_name,name = member.rsplit(' ',1)
                funcFlag = False
            print type_name,"|", name
            self.members.append(TypeStructureMember(name,type_name,funcFlag,specs))

    def __str__(self):
        if self.struc_type == "struct":
            string = "struct"
        else:
            string = "union"
        for spec in self.specs:
            string = string + " " + spec
        string = string + " " + self.name
        if self.BaseClasses != None:
            string = string + ":"
            for base in self.BaseClasses:
                string = string + " " + base +","
        string = string + "\n{\n"
        for member in self.members:
            #if member.ptr:
             #   string = string + " %s *%s;\n"%(member.type_name,member.name)
            #else:
            if len(self.specs) > 0:
                for spec in member.specs:
                    string = string + " %s"%spec
            string = string + " %s %s;\n"%(member.type_name,member.name)
        string = string + "};\n"
        return string

    def ConvertBaseClass(self):
        i = 0
        if self.BaseClasses != None:
            for base in self.BaseClasses:
                self.members.insert(i,TypeStructureMember("baseclass_"+str(i),base.strip(" :\n").rstrip(" :\n")))
                i = i + 1
            self.BaseClasses = None

def CheckMemberPrefix(data):
    if data.rfind("const ") > 0 and data.find(" (") == -1:
        if data.rfind(">") == -1:
            return data.rfind("const ")
        elif data.rfind(">") < data.rfind("const "):
            return data.rfind("const ")

    if data.rfind("volatile ") > 0 and data.find(" (") == -1:
        if data.rfind(">") == -1:
            return data.rfind("volatile ")
        elif data.rfind(">") < data.rfind("volatile "):
            return data.rfind("volatile ")
    return -1


class EnumTypeStructure(TypeStructure):
    def CreateMembers(self,data):
        if data == "":
            return
        data = data.split('\n')
        specs = ()
        for member in data:
            member = member.strip('\n ;').rstrip('\n ;')
            #print member
            funcFlag = False
            type_name, name = member.split("=")
            type_name = type_name.strip('\n ;').rstrip('\n ;')
            name = name.strip('\n ;').rstrip('\n ;')
            print type_name,"|", name
            self.members.append(TypeStructureMember(name,type_name,funcFlag,specs))

    def Parse(self):
        line = self.getline()

        while line != None:
            #print line
            if line.lower().startswith("enum"):
                self.struc_type = "enum"
                self.name = line.split(" ",1).strip(" \n;").rstrip(" \n;")
                self.BaseClasses = None
                self.specs = ()
                members = self.GetMembers()
                print "Name = %s"%self.name
                return members

    def __str__(self):
        if self.struc_type == "enum":
            string = "enum"
        string = string + " " + self.name
        string = string + "\n{\n"
        for member in self.members:
            #if member.ptr:
             #   string = string + " %s *%s;\n"%(member.type_name,member.name)
            #else:
            string = string + " %s = %s;\n"%(member.type_name,member.name)
        string = string + "};\n"
        return string

def ExtractSpecs(data):
    specs = ()
    while CheckSpecial(data):
        temp = data.strip(" \n;").split(" ",1)
        specs = specs + (temp[0].strip(" \n;"),)
        data = temp[1].strip(" \n;")
    return specs, data


        

class IdaTextTypes(object):
    def __init__(self,data = None):
        self.data = data
        self.curID = 0
        #self.specs = ()
        self.structures = []
        self.Parse()
        #self.app = QApplication(sys.argv)
        #self.DuplicateResolver = DuplicateResolver(self)
        self.DependsResolver = DependsResolver(self)


    #def Resolve(self):
        #self.DuplicateResolver.Resolve()
        
    def CheckSpecial(self,data):
        for special in specials:
            if data.startswith(special):
                return True
        return False
        
    def getline(self):
        if self.data == "":
            return None
        
        ret = self.data.split('\n',1)
        #print ret
        if len(ret) > 1:
            self.data = ret[1]
        else: 
            self.data = ""
        return ret[0]
    
    def GetMembers(self):
        #members = self.data.split('{\n',1)[1].split('\n}',1)
        members = self.data[self.data.find("{")+1:self.data.find("}")]
        #print members
        self.data = self.data[self.data.find("}"):]
        return members
    
    def Parse(self):
        line = self.getline()
        
        while line != None:
            #print line
            if line.lower().startswith("struct") or line.lower().startswith("const struct") or line.lower().startswith("union"):
                if line.lower().startswith("union"):
                    struc_type = "union"
                else:
                    struc_type = "struct"
                specs = ()
                body = line.split(" ",1)
                if line.lower().startswith("const struct"):
                    body = body[1]
                    body = body.split(" ",1)
                if len(body) > 1:
                    body = body[1]
                    if body.find("ATL::CSimpleArray<unsigned") != -1:
                        print "ok"
                    spec_new = [body]
                    spec = spec_new
                    #print spec
                    while self.CheckSpecial(body):
                        spec_new = body.split(" ",1)
                        if self.CheckSpecial(spec_new[0]):
                            specs = specs + (spec_new[0],)
                            spec = spec_new
                            body = spec_new[1]
                        else:
                            break
                        #print spec
                        #print spec[0].startswith("__")
                        #spec_new = spec[1].split(" ",1)
                    #print spec
                    #print self.specs
                    if self.CheckSpecial(spec[0]):
                           spec.pop(0)
                    if spec[0].find(" : ") != -1:
                            spec = spec[0].rsplit(" : ",1)
                            spec.insert(1,": "+spec[1])
                            spec.pop()
                    if len(spec) > 1:
                        name = spec[0]
                        suffix = spec[1]
                    else:
                        name = spec[0]
                        suffix = None
                    members = self.GetMembers()
                    print "Name = %s"%name
                    #print "Members:\n"
                    #print members
                    struc = TypeStructure(name,members,specs,suffix,struc_type)
                    struc.id = self.curID
                    self.curID = self.curID + 1
                    if name not in self.structures:
                        self.structures.append(struc)
                    else:
                        print "Duplicated structure: %s"%name
            elif line.lower().startswith("enum"):
                struc_type = "enum"
                name = line.split(" ",1)[1].strip(" \n;").rstrip(" \n;")
                suffix = None
                specs = ()
                members = self.GetMembers()
                print "Name = %s"%name
                struc = EnumTypeStructure(name,members,specs,suffix,struc_type)
                struc.id = self.curID
                self.curID = self.curID + 1
                if name not in self.structures:
                    self.structures.append(struc)
                else:
                    print "Duplicated enum: %s"%name
            elif line.lower().startswith("typedef"):
                struc = TypeDef(line)
                struc.id = self.curID
                self.curID = self.curID + 1
                if struc.name not in self.structures:
                    self.structures.append(struc)
                else:
                    print "Duplicated typedef: %s"%struc.name
                print "Typedef: %s\n%s | %s\n"%(struc.name,struc.type_name,struc.fullName)
                print "------------------------------------------------------------------------"

            line = self.getline()
    def FixSTLNames(self):
        p = re.compile(r'\w*(<.*>)\w*')
        for struc in self.structures:
            while True:
                tok =  p.findall(struc.name)
                if len(tok) > 0:
                    old_name = struc.name
                    #print tok[0][1:tok[0].find(",")]
                    struc.name =  struc.name.replace(tok[0],"") +"_" + tok[0][1:tok[0].find(",")].rstrip(" *").strip(" *").replace(" ","_")
                    new_name = struc.name
                    print "old_name = %s\n New_name = %s"%(old_name,new_name)
                    for it_struc in self.structures:
                        if it_struc.struc_type == "typedef":
                            it_struc.name = it_struc.name.replace(old_name,new_name)
                            it_struc.type_name = it_struc.type_name.replace(old_name,new_name)
                            it_struc.fullName = it_struc.fullName.replace(old_name,new_name)
                            for member in it_struc.members:
                                member.type_name = member.type_name.replace(old_name,new_name).rstrip(" *").strip(" *")
                                if member.funcFlag:
                                    member.name = member.name.replace(old_name,new_name).rstrip(" *").strip(" *")
                        else:
                            it_struc.name = it_struc.name.replace(old_name,new_name).rstrip(" *").strip(" *")
                            if it_struc.BaseClasses != None:
                                for base in it_struc.BaseClasses:
                                    idx = it_struc.BaseClasses.index(base)
                                    it_struc.BaseClasses[idx] = it_struc.BaseClasses[idx].replace(old_name,new_name).rstrip(" *").strip(" *")
                            if it_struc.struc_type != "enum":
                                for member in it_struc.members:
                                    member.type_name = member.type_name.replace(old_name,new_name).rstrip(" *").strip(" *")
                                    if member.funcFlag:
                                        member.name = member.name.replace(old_name,new_name).rstrip(" *").strip(" *")
                else:
                    break
        
class DependsResolver(object):
    def __init__(self, ITT):
        self.ITT = ITT
        self.TypesOrdinals = {}
        self.SortedStructOrdinals = []
        self.structures = []
        self.notResolvedType = {}
        self.currBaseOrdinals = ()

    def GetOrdinalByStructName(self,name):
        for ordinal in self.TypesOrdinals:
            if self.TypesOrdinals[ordinal].name == name:
                return ordinal
        return -1

    def BuldDependences(self):
        for struc in self.ITT.structures:
            self.structures.append(struc)
            self.TypesOrdinals[struc.id] = struc
        for struc in self.ITT.structures:
            if struc.BaseClasses != None:
                for base in struc.BaseClasses:
                    struc.BaseClassesDepends.append(self.GetOrdinalByStructName(base))
            for member in struc.members:
                if member.funcFlag:
                    member.depended = -1
                    struc.membersDepends.append(member.depended)
                else:
                    member.depended = self.GetOrdinalByStructName(member.type_name)
                    struc.membersDepends.append(member.depended)

    def CheckMembersDepends(self,struc):
        for ordinal in struc.membersDepends:
            if ordinal != -1 and ordinal not in self.SortedStructOrdinals and ordinal != struc.id:
                return False
        if struc.BaseClasses != None:
            for ordinal in struc.BaseClassesDepends:
                if ordinal !=  -1 and ordinal not in self.SortedStructOrdinals and ordinal != struc.id:
                    return False
        return True


    def BuildDependTree(self):
        i = 0
        pred = 0
        self.notResolvedType = {}
        while len(self.structures) > 0:
            for struc in self.structures:
                if self.CheckMembersDepends(struc):
                    self.SortedStructOrdinals.append(struc.id)
                    self.structures.remove(struc)
            i = i + 1
            if len(self.structures) == pred:
                self.notResolvedType = {}
                for bad_struc in self.structures:
                    print "Not resolved structure: %s"%bad_struc.name
                    notResolvedDepends = ()
                    if bad_struc.BaseClasses != None:
                        for depend in bad_struc.BaseClassesDepends:
                            if depend != -1 and depend not in self.SortedStructOrdinals and depend != bad_struc.id:
                                print "Not resolved baseclass depend: %s"%self.TypesOrdinals[depend].name
                                notResolvedDepends = notResolvedDepends + (depend,)
                    for depend in bad_struc.membersDepends:
                        if depend != -1 and depend not in self.SortedStructOrdinals and depend != bad_struc.id:
                            print "Not resolved depend: %s"%self.TypesOrdinals[depend].name
                            notResolvedDepends = notResolvedDepends + (depend,)
                    print "\n---------------------------------------------------------------------\n"
                    if len(notResolvedDepends) > 0:
                        self.notResolvedType[bad_struc.id] = notResolvedDepends
                for baseOrdinal in self.notResolvedType:
                    if self.CheckChain(baseOrdinal):
                        break


                print "New iteration for resolve loop dependency"
            pred = len(self.structures)
            if i > 1000:
                print "Infinity loop!"
                exit(0)
        return self.SortedStructOrdinals

    def CheckChain(self,base_ordinal):
        self.currBaseOrdinals = self.currBaseOrdinals + (base_ordinal,)
        for dep_ord in self.notResolvedType[base_ordinal]:
            if dep_ord in self.currBaseOrdinals and dep_ord not in self.SortedStructOrdinals:
                self.SortedStructOrdinals.append(dep_ord)
                self.currBaseOrdinals = ()
                return True
            elif dep_ord in self.SortedStructOrdinals:
                del(self.notResolvedType[dep_ord])
            else:
                if self.CheckChain(dep_ord):
                    return True

        return False












def main(argv):
    #print len(argv)
#     txt = '''struct tagOIFI
# {
#   unsigned int cb;
#   int fMDIApp;
#   HWND__ *hwndFrame;
#   HACCEL__ *haccel;
#   unsigned int cAccelEntries;
# };'''
#     struc = TypeStructure("",txt)
#     print struc
#     return
#     app = QApplication(sys.argv)
# # form = MyWindow()
#     form = DuplicateResolver(None)
#     print "NOT OK!!!"
#     form.show()
#     print "OK!!!"
#     #form.show()
#     app.exec_()
#     exit(0)
#     if len(argv) < 2:
#         print "Usage: %s filename p"
#         return
    #f = open(argv[1],"r")
    if len(argv) <= 2:
        f = open("mfc_example_full.h","r")
        data = f.read()
        #print data
        ITT = IdaTextTypes(data)
        print "Structures num = %d"%len(ITT.structures)
        f.close()

        type_names = {}
        depend_type_names = {}

        for struc in ITT.structures:
            type_names[struc.name] = 0
            if struc.struc_type != "enum":
                for member in struc.members:
                    if member.type_name == "const":
                        print "Ok"
                    depend_type_names[member.type_name] = 0

        # print "Type names:\n"
        # for name in type_names:
        #     print name
        # print("\n\nMembers type names:\n")
        # for name in depend_type_names:
        #     print name
        # print("\n\nMembers not exist type names:\n")
        # for name in depend_type_names:
        #     if name not in type_names and name not in BaseTypes:
        #         for struc in ITT.structures:
        #             if struc.struc_type == "typedef" and struc.type_name == name:
        #                 print "%s typedef"%name
        #                 break
        #         if struc.struc_type != "typedef":
        #             print name

        ITT.DependsResolver.BuldDependences()
        tree = ITT.DependsResolver.BuildDependTree()
        for struc in ITT.structures:
            print "Struct name: %s (%d)\nBaseClasseseDepends: %s\nDependences: %s"%(struc.name,struc.id,struc.BaseClassesDepends,struc.membersDepends)
        #exit(0)
        ITT.FixSTLNames()
        resolver = DuplicateResolver(ITT)
        struct_dict = resolver.Resolve()
        ITT.structures = struct_dict
        # for elem in struct_dict:
        #     ITT.structures.append(struct_dict[elem])
        print "Iter 2"
        struct_dict = resolver.Resolve()
        pickle.dump( ITT, open( "temp.p", "wb" ) )
    else:
        ITT = pickle.load( open( "temp.p", "rb" ) )
    structure_dict = {}

    tree = ITT.DependsResolver.BuildDependTree()
    # for struc in ITT.structures:
    #     if struc.suffix != None and len(struc.suffix.split(', ',1)) > 1:
    #         print "Double baseclass structure: %s"%struc.name
    #         struc.ConvertBaseClass()
    #         print struc
    #     if struc.name not in structure_dict:
    #         structure_dict[struc.name] = struc
    #     else:
    #         print "Duplicated structure: %s"%struc.name
    #         print struc
    #         print "Dublicated:"
    #         print structure_dict[struc.name]



    

            
app = QApplication(sys.argv)
if __name__ == "__main__": main(sys.argv)


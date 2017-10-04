from idaapi import *
import idaapi
from idc import *
import idc
import os, sys
def find_ida_dir():
    name = "idaq.exe"
    for p in sys.path:
        for root, dirs, files in os.walk(p):
            if name in files:
                return root

class ConfigFeaturesChooser(idaapi.Choose2):

    def __init__(self,items,obj):
        self.obj = obj
        idaapi.Choose2.__init__(self,"Features",[["Feature name",40],["Status",10]],embedded=True,width=100)
        self.n = 0
        self.items = []
        self.make_items(items)

    def make_items(self,items):
        for name, status in items:
            self.items.append([name,"Enabled" if status else "Disabled"])

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnSelectLine(self, n):
        name, status = self.items.pop(n)
        self.items.insert(n,[name,"Enabled" if status == "Disabled" else "Disabled"])
        self.obj.RefreshField(self.obj.cEChooser)

    def GetItems(self):
        ret = []
        for name, status in self.items:
            ret.append((name,True if status == "Enabled" else False))
        return ret

class ConfigForm(Form):

    def __init__(self, feats):
        self.EChooser = ConfigFeaturesChooser(feats,self)
        Form.__init__(self,
r"""HexRaysPyTools features config
Double click for switch feature.

<Embedded chooser:{cEChooser}>
""", {'cEChooser' : Form.EmbeddedChooserControl(self.EChooser)})

    def Go(self):
        self.Compile()
        ok = self.Execute()
        #print "Ok = %d"%ok
        if ok == 1:
            #print sel
            #print len(sel)
            return self.EChooser.GetItems()
        return


class MyForm3(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self):
        self.__n = 0
        Form.__init__(self,
r"""BUTTON YES* Yeah
BUTTON NO Nope
BUTTON CANCEL NONE
Dropdown list test
{FormChangeCb}
<Dropdown list (readonly):{cbReadonly}> <Add element:{iButtonAddelement}> <Set index:{iButtonSetIndex}>
<Dropdown list (editable):{cbEditable}> <Set string:{iButtonSetString}>
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'cbReadonly': Form.DropdownListControl(
                        items=["red", "green", "blue"],
                        readonly=True,
                        selval=1),
            'cbEditable': Form.DropdownListControl(
                        items=["1MB", "2MB", "3MB", "4MB"],
                        readonly=False,
                        selval="4MB"),
            'iButtonAddelement': Form.ButtonInput(self.OnButtonNop),
            'iButtonSetIndex': Form.ButtonInput(self.OnButtonNop),
            'iButtonSetString': Form.ButtonInput(self.OnButtonNop),
        })


    def OnButtonNop(self, code=0):
        """Do nothing, we will handle events in the form callback"""
        pass

    def OnFormChange(self, fid):
        if fid == self.iButtonSetString.id:
            s = idc.AskStr("none", "Enter value")
            if s:
                self.SetControlValue(self.cbEditable, s)
        elif fid == self.iButtonSetIndex.id:
            s = idc.AskStr("1", "Enter index value:")
            if s:
                try:
                    i = int(s)
                except:
                    i = 0
                self.SetControlValue(self.cbReadonly, i)
        elif fid == self.iButtonAddelement.id:
            # add a value to the string list
            self.__n += 1
            self.cbReadonly.add("some text #%d" % self.__n)
            # Refresh the control
            self.RefreshField(self.cbReadonly)
        elif fid == -2:
            s = self.GetControlValue(self.cbEditable)
            print "user entered: %s" % s
            sel_idx = self.GetControlValue(self.cbReadonly)

        return 1

class MyForm4(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self):
        self.selected = ""
        Form.__init__(self, r"""STARTITEM 0
Create struct

<Struct name:{cStrArg}><Struct size:{numSize}>
<Field size :{numFieldSize}>                                        <Align:{ckAlign}>{gAlign}>

""", {
            'cStrArg':Form.StringInput(),
            'numSize':Form.StringInput(swidth=10),
            'numFieldSize':Form.DropdownListControl(
                        items=["1", "2", "4", "8"],
                        readonly=False,
                        selval="4"),
            'gAlign': Form.ChkGroupControl(("ckAlign",)),
        })

    def Go(self):
        self.Compile()
        self.ckAlign.checked = True
        self.numSize.value = "0"
        ok = self.Execute()
        #print "Ok = %d"%ok
        if ok == 1:
            sel = self.selected
            #print sel
            #print len(sel)
            print "Name = %s, size = %d, field size = %d, isAligh = %s"%(self.cStrArg.value,self.numSize.value,int(self.numFieldSize.value),"True" if self.ckAlign.checked else "False")

            return sel
        return ""

    def OnFormChange(self, fid):

        return 1


class MyForm2(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self):
        self.selected = ""
        Form.__init__(self, r"""STARTITEM 0
Duplicate resolver

Detected type duplicate
You must select a variant

Default rule if pressed "OK":

Import from storage - 'Existing type' from storage will replaced by type in IDA
Export to storage - 'Existing type' from IDA will replaced by type in storage

You can edit structure and use appropriate button to save the edited type

{FormChangeCb}
<Existing type:{txtMultiLineText}><##Keep exist type:{iButton1}>
<Type for replace:{txtMultiLineText2}><##Replace type:{iButton2}>
<Test file:{iFileInput}>

""", {
            'txtMultiLineText': Form.MultiLineTextControl(text="",width=100),
            'txtMultiLineText2': Form.MultiLineTextControl(text="",width=100),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
            'iFileInput': Form.FileInput(open=True,hlp='*.db',value=os.path.join(find_ida_dir(),"TypeStorage.db"))
        })

    def Go(self,text1='aaaa',text2='dddd'):
        self.Compile()
        self.txtMultiLineText.text = COLSTR(text1,SCOLOR_ERROR)
        self.txtMultiLineText2.text = text2
        ok = self.Execute()
        #print "Ok = %d"%ok
        if ok == 1:
            sel = self.selected
            #print sel
            #print len(sel)
            return sel
        return ""

    def OnFormChange(self, fid):
        #print(">>fid:%d" % fid)
        if fid == self.txtMultiLineText.id:
            pass
        elif fid == -2:
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

# --------------------------------------------------------------------------
def test_multilinetext(execute=True):
    """Test the multilinetext and combobox controls"""
    f = MyForm2()
    f, args = f.Compile()
    #print args
    if execute:
        ok = f.Execute()
    else:
        print args[0]
        print args[1:]
        ok = 0

    if ok == 1:
        assert f.txtMultiLineText.text == f.txtMultiLineText.value
        print f.txtMultiLineText.text
        print f.txtMultiLineText.value

    f.Free()


#test_multilinetext()

f = ConfigForm((["AAAAA",True],["BBBBBB",False],["FFFFFF",True]))
# print f.Go("aaaaaaaaa",'bbbbbbbbbb')
print f.Go()
# f = MyForm3()
# f, args = f.Compile()
# ok = f.Execute()

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


from idaapi import *
from idc import *

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

""", {
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

f = MyForm2()
print f.Go("aaaaaaaaa",'bbbbbbbbbb')

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


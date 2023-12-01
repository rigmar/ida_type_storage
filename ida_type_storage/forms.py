from __future__ import division
from __future__ import print_function
from builtins import str
from builtins import range
# from past.utils import old_div
from builtins import object
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5 import QtGui, QtCore, QtWidgets
from difflib import *
import idc
from idaapi import *
import ida_kernwin
import idaapi
qtMode = 3
from collections import OrderedDict

fSQL = True

def find_ida_dir():
    return idc.idadir()


def format(color, style=''):
    """Return a QTextCharFormat with the given attributes.
    """
    _color = QColor()
    # _color.setNamedColor(color)
    # _color.setHsl(100,100,100)
    _color.setRed(204)
    _color.setGreen(255)
    _color.setBlue(230)
    _format = QTextCharFormat()
    # _format.setForeground(_color)
    _format.setBackground(_color)
    if 'bold' in style:
        _format.setFontWeight(QFont.Bold)
    if 'italic' in style:
        _format.setFontItalic(True)

    return _format

class MergedResult(object):

    def __init__(self,diff = None):
        self.leftText = {}
        self.rigthText = {}
        self.mergedText = {}
        self.diffs = {'-': {}, '+': {}}
        if diff is not None:
            self.parseDiff(diff)
            self.GetMergedText()

    def parseDiff(self,diff):
        lineNumL = 1
        lineNumR = 1
        prevType = ""
        for l in diff:
            lineType = l[:1]
            line = l[2:]
            if lineType == prevType:
                df = lineNumL - lineNumR
                if df < 0:
                    for s in range(0, abs(df)):
                        self.leftText[lineNumL] = (lineNumL, "\n", "!")
                        lineNumL += 1
                elif df > 0:
                    for s in range(0, df):
                        self.rigthText[lineNumR] = (lineNumR, "\n", "!")
                        lineNumR += 1
            if lineType == " ":
                df = lineNumL - lineNumR
                if df < 0:
                    for s in range(0,abs(df)):
                        self.leftText[lineNumL]=(lineNumL, "\n", "!")
                        lineNumL +=1
                elif df > 0:
                    for s in range(0,df):
                        self.rigthText[lineNumR]=(lineNumR, "\n", "!")
                        lineNumR +=1

                self.leftText[lineNumL]=(lineNumL,line,lineType)
                self.rigthText[lineNumR]=(lineNumR,line,lineType)
                lineNumL += 1
                lineNumR += 1
                prevType = ""
            if lineType == "-":
                self.leftText[lineNumL]=(lineNumL,line,lineType)
                prevType = lineType
                lineNumL += 1
            if lineType == "+":
                self.rigthText[lineNumR]=(lineNumR, line, lineType)
                prevType = lineType
                lineNumR += 1
            if lineType == "?":
                #self.diffs.append((lineNumL if prevType == "-" else lineNumR,prevType) + (self.parseDiffLine(line),))
                self.diffs[prevType][(lineNumL if prevType == "-" else lineNumR) - 1] = self.parseDiffLine(line)
                prevType = ""


    def parseDiffLine(self,line):
        raw = []
        i = 0
        line = line.rstrip("\n")
        for i, ch in enumerate(line):
            if ch != " ":
                raw.append((i,ch))
        ret = []
        i = 0
        if len(raw) > 1:
            startPos = raw[i][0]
            prevPos = startPos
            prevCH = raw[i][1]
            i += 1
            while i < len(raw):

                if prevPos + 1 == raw[i][0] and prevCH == raw[i][1]:
                    prevPos += 1
                else:
                    ret.append((startPos,prevPos,prevCH))
                    startPos = raw[i][0]
                    prevPos = startPos
                    prevCH = raw[i][1]
                i += 1
            ret.append((startPos, prevPos, prevCH))
        else:
            ret.append((raw[i][0], raw[i][0], raw[i][1]))

        return ret

    def GetMergedText(self):
        for lineNum in self.leftText:
            lineNum, line, lnType = self.leftText[lineNum]
            if lnType == " ":
                self.mergedText[lineNum] = (lineNum, line, lnType)
            elif lnType == "!":
                self.mergedText[lineNum] = (lineNum, self.rigthText[lineNum][1],self.rigthText[lineNum][2])
            elif lnType == "-":
                if self.rigthText[lineNum][2] == "!":
                    self.mergedText[lineNum] = (lineNum, "\n","!")
                else:
                    self.mergedText[lineNum] = (lineNum, line, lnType)
        return self.mergedText

try:
    UNICODE_EXISTS = bool(type(unicode))
except NameError:
    unicode = lambda s: str(s)


from PyQt5 import QtGui, QtCore, QtWidgets

#print("PyQt5 Try")


class LNTextEdit(QtWidgets.QFrame):
    class NumberBar(QtWidgets.QWidget):

        def __init__(self, edit):
            QtWidgets.QWidget.__init__(self, edit)

            self.edit = edit
            self.adjustWidth(1)

        def paintEvent(self, event):
            self.edit.numberbarPaint(self, event)
            QtWidgets.QWidget.paintEvent(self, event)

        def adjustWidth(self, count):
            width = self.fontMetrics().width(unicode(count))
            if self.width() != width:
                self.setFixedWidth(width)

        def updateContents(self, rect, scroll):
            if scroll:
                self.scroll(0, scroll)
            else:
                # It would be nice to do
                # self.update(0, rect.y(), self.width(), rect.height())
                # But we can't because it will not remove the bold on the
                # current line if word wrap is enabled and a new block is
                # selected.
                self.update()



    class PlainTextEdit(QtWidgets.QPlainTextEdit):
        def __init__(self, *args):
            QtWidgets.QPlainTextEdit.__init__(self, *args)
            self.setFrameStyle(QtWidgets.QFrame.NoFrame)
            self.zoomWheelEnabled = 0
            self.highlight()
            # self.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
            self.cursorPositionChanged.connect(self.highlight)

        def dragEnterEvent(self, event):
            data = event.mimeData()
            urls = data.urls()
            if (urls and urls[0].scheme() == 'file'):
                event.acceptProposedAction()

        def dragMoveEvent(self, event):
            data = event.mimeData()
            urls = data.urls()
            if (urls and urls[0].scheme() == 'file'):
                event.acceptProposedAction()

        def dropEvent(self, event):
            data = event.mimeData()
            urls = data.urls()
            if (urls and urls[0].scheme() == 'file'):
                txt = "\n".join([unicode(url.path())[1:] for url in urls])  # remove 1st / char
                self.insertPlainText(txt)

        def zoom_in(self):
            font = self.document().defaultFont()
            size = font.pointSize()
            if size < 28:
                size += 2
                font.setPointSize(size)
            self.setFont(font)

        def zoom_out(self):
            font = self.document().defaultFont()
            size = font.pointSize()
            if size > 6:
                size -= 2
                font.setPointSize(size)
            self.setFont(font)

        def wheelEvent(self, event, forward=True):
            if event.modifiers() == QtCore.Qt.ControlModifier:
                if self.zoomWheelEnabled == 1:
                    if event.delta() == 120:
                        self.zoom_in()
                    elif event.delta() == -120:
                        self.zoom_out()
                event.ignore()
            QtWidgets.QPlainTextEdit.wheelEvent(self, event)

        def highlight(self):
            hi_selection = QtWidgets.QTextEdit.ExtraSelection()

            hi_selection.format.setBackground(self.palette().alternateBase())
            hi_selection.format.setProperty(QtGui.QTextFormat.FullWidthSelection, 1)  # QtCore.QVariant(True)
            hi_selection.cursor = self.textCursor()
            hi_selection.cursor.clearSelection()

            self.setExtraSelections([hi_selection])

        def numberbarPaint(self, number_bar, event):
            font_metrics = self.fontMetrics()
            current_line = self.document().findBlock(self.textCursor().position()).blockNumber() + 1

            block = self.firstVisibleBlock()
            line_count = block.blockNumber()
            painter = QtGui.QPainter(number_bar)
            painter.fillRect(event.rect(), self.palette().base())

            # Iterate over all visible text blocks in the document.
            while block.isValid():
                line_count += 1
                block_top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()

                # Check if the position of the block is out side of the visible
                # area.
                if not block.isVisible() or block_top >= event.rect().bottom():
                    break

                # We want the line number for the selected line to be bold.
                if line_count == current_line:
                    font = painter.font()
                    font.setBold(True)
                    painter.setFont(font)
                else:
                    font = painter.font()
                    font.setBold(False)
                    painter.setFont(font)

                # Draw the line number right justified at the position of the line.
                paint_rect = QtCore.QRect(0, int(block_top), number_bar.width(), font_metrics.height())
                painter.drawText(paint_rect, QtCore.Qt.AlignRight, unicode(line_count))

                block = block.next()

            painter.end()

    def __init__(self, *args):
        QtWidgets.QFrame.__init__(self, *args)

        self.setFrameStyle(QtWidgets.QFrame.StyledPanel | QtWidgets.QFrame.Sunken)

        self.edit = self.PlainTextEdit()
        self.number_bar = self.NumberBar(self.edit)

        hbox = QtWidgets.QHBoxLayout(self)
        hbox.setSpacing(0)
        hbox.setContentsMargins(0, 0, 0, 0)  # setMargin
        hbox.addWidget(self.number_bar)
        hbox.addWidget(self.edit)

        self.edit.blockCountChanged.connect(self.number_bar.adjustWidth)
        self.edit.updateRequest.connect(self.number_bar.updateContents)

    def text(self):
        return unicode(self.edit.toPlainText())

    def getText(self):
        return unicode(self.edit.toPlainText())

    def setText(self, text):
        self.edit.setPlainText(text)

    def insertText(self, text):
        self.edit.insertPlainText(text)

    def insertPlainText(self, text):
        self.insertText(text)

    def isModified(self):
        return self.edit.document().isModified()

    def setModified(self, modified):
        self.edit.document().setModified(modified)

    def setLineWrapMode(self, mode):
        self.edit.setLineWrapMode(mode)

    def setWrap(self, state):
        if state == 0:
            self.edit.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        else:
            self.edit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)

    def setReadOnly(self, state):
        self.edit.setReadOnly(state)

    def setReadOnlyStyle(self, state):
        if state == 1:
            mainWindowBgColor = QtWidgets.QPalette().color(QtWidgets.QPalette.Window)
            self.setStyleSheet(
                'QPlainTextEdit[readOnly="true"] { background-color: %s;} QFrame {border: 0px}' % mainWindowBgColor.name())
            self.setHighlight(0)
        else:
            self.setStyleSheet('')
            self.setHighlight(1)

    def setFontSize(self, value):
        font = self.edit.document().defaultFont()
        if value > 6 and value < 28:
            font.setPointSize(value)
            self.edit.setFont(font)

    def getFontSize(self):
        font = self.edit.document().defaultFont()
        size = font.pointSize()
        return size

    def resetFontSize(self):
        font = self.edit.document().defaultFont()
        font.setPointSize(8)
        self.edit.setFont(font)

    def setZoom(self, mode):
        if mode == 0:
            self.edit.zoomWheelEnabled = 0
        else:
            self.edit.zoomWheelEnabled = 1

    def setHighlight(self, state):
        txtEdit = self.edit
        if state == 0:
            txtEdit.cursorPositionChanged.disconnect()
            txtEdit.setExtraSelections([])
        else:
            txtEdit.cursorPositionChanged.connect(txtEdit.highlight)

    def setMergeText(self, lines, diffs, left=True):
        self.diffs = diffs
        self.lines = lines
        line_start = 0
        for lineNum, line, lnType in lines.values():
            line = line.rstrip("\n")
            # print (line)
            self.edit.appendPlainText(line)
            if left is not None:
                if lineNum in diffs["-" if left else "+"]:
                    for start_diff_pos, end_diff_pos, diff_type in diffs["-" if left else "+"][lineNum]:
                        hi_selection = QTextEdit.ExtraSelection()
                        hi_selection.cursor = QTextCursor(self.edit.document())
                        hi_selection.cursor.setPosition(line_start + start_diff_pos)
                        hi_selection.cursor.setPosition(line_start + end_diff_pos + 1, QTextCursor.KeepAnchor)
                        hi_selection.cursor.setCharFormat(format("green"))
                        hi_selection.cursor.clearSelection()
                else:
                    if lnType != " ":
                        hi_selection = QTextEdit.ExtraSelection()
                        hi_selection.cursor = QTextCursor(self.edit.document())
                        hi_selection.cursor.setPosition(line_start)
                        hi_selection.cursor.setPosition(line_start + len(line), QTextCursor.KeepAnchor)
                        hi_selection.cursor.setCharFormat(format("green"))
                        hi_selection.cursor.clearSelection()
            line_start += (len(line) + 1)



class DublicateResolverUI(QDialog):
    def __init__(self,leftText = "", rightText = "",fToStorage = True):
        flags = Qt.WindowFlags(Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint | Qt.WindowMaximizeButtonHint)
        super(DublicateResolverUI, self).__init__(flags=flags)
        self.textEdits = []
        self.sel = 1
        self.selText = ""
        self.fToStorage = fToStorage
        self.leftText = leftText.splitlines(True)
        self.rightText = rightText.splitlines(True)
        self.MR = MergedResult(self.GetDiff(self.leftText,self.rightText))

        self.initUI()


    def initUI(self):
        qlLeft = QLabel('Existing type in the repository' if self.fToStorage else "Existing local type")
        qlRight = QLabel('New type from the repository' if not self.fToStorage else "New local type")
        qlMerged = QLabel('Merged type')

        self.textEdit1 = LNTextEdit()
        self.textEdit1.edit.cursorPositionChanged.connect(self.highlight)
        self.textEdit2 = LNTextEdit()
        self.textEdit2.edit.cursorPositionChanged.connect(self.highlight)
        self.textEdit3 = LNTextEdit()
        self.textEdit3.edit.cursorPositionChanged.connect(self.highlight)
        self.textEdits = [self.textEdit1.edit,self.textEdit2.edit,self.textEdit3.edit]
        # textEdit1 = QTextEdit()
        # textEdit2 = QTextEdit()
        # textEdit3 = QTextEdit()

        #hi = PythonHighlighter(textEdit1)
        #print hi.currentBlock().text()

        #self.textEdit1.setText("AAAAAAAAAAAABBBBBBBBB\nCCCCCCCCCDDDDDDDDDD\nAAAAAAAAAAAABBBBBBBBB\nAAAAAAAAAAAABBBBBBBBB\nAAAAAAAAAAAABBBBBBBBB\nAAAAAAAAAAAABBBBBBBBB\nAAAAAAAAAAAABBBBBBBBB")
        # self.textEdit1.edit.appendPlainText("DDDDDDDDD")
        # self.textEdit1.edit.appendPlainText("DDDDDDDDD")
        #self.textEdit1.setReadOnly(True)
        #print hi.currentBlock().text()

        grid = QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(qlLeft, 0, 1)
        grid.addWidget(self.textEdit1, 1, 1)

        grid.addWidget(qlMerged, 0, 3)
        grid.addWidget(self.textEdit2, 1, 3)

        grid.addWidget(qlRight, 0, 5)
        grid.addWidget(self.textEdit3, 1, 5)

        btLeftAll = QPushButton("Use left")
        grid.addWidget(btLeftAll,2,1)
        btLeft = QPushButton(">")
        grid.addWidget(btLeft,1,2)

        btLeft.clicked.connect(self.Left)
        btLeftAll.clicked.connect(self.LeftAll)

        btRightAll = QPushButton("Use right")
        grid.addWidget(btRightAll, 2, 5)
        btRight = QPushButton("<")
        grid.addWidget(btRight, 1, 4)

        btRight.clicked.connect(self.Right)
        btRightAll.clicked.connect(self.RightAll)

        btUseMerged = QPushButton("Use merged")
        grid.addWidget(btUseMerged,2,3)

        btUseMerged.clicked.connect(self.UseMerged)

        self.setLayout(grid)
        # self.resize(self.sizeHint())r
        QP = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setSizePolicy(QP)
        # print self.size()
        mainGeo = QCoreApplication.instance().desktop().screenGeometry()
        for w in QCoreApplication.instance().allWidgets():
            if type(w) == QMainWindow:
                mainGeo = w.geometry()
                break
        #mainGeo.setHeight(mainGeo.height() - 300)
        #mainGeo.setWidth(mainGeo.width() - 300)
        #print mainGeo

        #print QCoreApplication.instance().desktop().screenGeometry()
        self.setMinimumSize(mainGeo.width()//4*3,mainGeo.height()//4*3)
        #print self.size()
        #self.resize(QSize(rec.width() - 400, rec.height() - 400))
        # self.setGeometry(600, 600, 600, 600)
        self.setWindowTitle('Review')
        self.textEdit1.setMergeText(self.MR.leftText, self.MR.diffs)
        self.textEdit3.setMergeText(self.MR.rigthText, self.MR.diffs, False)
        self.textEdit2.setMergeText(self.MR.GetMergedText(), self.MR.diffs, None)
        self.textEdit1.setReadOnly(True)
        self.textEdit3.setReadOnly(True)


    def highlight(self):
        # print (self.sender())
        # if self.sender() == self.textEdit1.edit:
        #     print ("same")
        # print self.toPlainText()
        # print self
        # obj = self if self.sender() is None else self.sender()
        hi_selection = QTextEdit.ExtraSelection()

        hi_selection.format.setBackground(self.sender().palette().alternateBase())
        hi_selection.format.setProperty(QTextFormat.FullWidthSelection, QVariant(True))
        hi_selection.cursor = self.sender().textCursor()
        cursor = hi_selection.cursor
        line_num = cursor.blockNumber()
        hi_selection.cursor.clearSelection()

        self.sender().setExtraSelections([hi_selection])
        for edit in self.textEdits:
            if edit.textCursor().blockNumber() != line_num:
                hi_selection = QTextEdit.ExtraSelection()

                hi_selection.format.setBackground(edit.palette().alternateBase())
                hi_selection.format.setProperty(QTextFormat.FullWidthSelection, QVariant(True))
                bl = edit.document().findBlockByNumber(line_num)
                cr = edit.textCursor()
                cr.setPosition(bl.position())
                # print ("pos = %d"%bl.position())
                # print ("len = %d"%bl.length())
                edit.setTextCursor(cr)
                hi_selection.cursor = edit.textCursor()
                hi_selection.cursor.clearSelection()

                edit.setExtraSelections([hi_selection])

    def Left(self):
        line_num = self.textEdit2.edit.textCursor().blockNumber() + 1
        ct = self.textEdit2.lines[line_num]
        line = self.textEdit1.lines[line_num][1]
        self.textEdit2.lines[line_num] = (ct[0], line, ct[2])
        self.textEdit2.edit.document().clear()
        self.textEdit2.setMergeText(self.textEdit2.lines,self.textEdit2.diffs,None)
        block = self.textEdit2.edit.document().findBlockByNumber(line_num)
        cr = self.textEdit2.edit.textCursor()
        cr.setPosition(block.position())
        self.textEdit2.edit.setTextCursor(cr)

    def Right(self):
        line_num = self.textEdit2.edit.textCursor().blockNumber() + 1
        ct = self.textEdit2.lines[line_num]
        line = self.textEdit3.lines[line_num][1]
        self.textEdit2.lines[line_num] = (ct[0], line, ct[2])
        self.textEdit2.edit.document().clear()
        self.textEdit2.setMergeText(self.textEdit2.lines,self.textEdit2.diffs,None)
        block = self.textEdit2.edit.document().findBlockByNumber(line_num)
        cr = self.textEdit2.edit.textCursor()
        cr.setPosition(block.position())
        self.textEdit2.edit.setTextCursor(cr)

    def LeftAll(self):
        self.sel = 1
        self.close()

    def RightAll(self):
        self.sel = 2
        self.close()

    def UseMerged(self):
        self.sel = 0
        self.close()

    def closeEvent(self, QCloseEvent):
        edit = None
        if self.sel == 0:
            self.selText = self.textEdit2.edit.toPlainText()
        elif self.sel == 1:
            self.selText = self.textEdit1.edit.toPlainText()
        elif self.sel == 2:
            self.selText = self.textEdit3.edit.toPlainText()

    @staticmethod
    def GetDiff(s1,s2):
        d = Differ()

        result = list(d.compare(s1, s2))
        return result
    def Go(self):
        self.setWindowModality(Qt.ApplicationModal)
        # self.setWindowModality(Qt.WindowModal)
        oldTo = idaapi.set_script_timeout(0)
        res = self.exec_()
        idaapi.set_script_timeout(oldTo)
        return res

class DuplicateResolverForm(Form):
    duplicate_form_text = r"""STARTITEM 0
    Duplicate resolver
    %s
    Detected type duplicate
    You must select a variant

    Default rule if pressed "OK" or "Cancel":

    Import from storage - Type in IDA will be replaced by type from storage
    Export to storage - Type in storage will be replaced by type from IDA

    You can edit structure and use appropriate button to save the edited type

    {FormChangeCb}
    <%s:{txtMultiLineText}><##%s:{iButton1}>
    <%s:{txtMultiLineText2}><##%s:{iButton2}>

    """

    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self,fToStorage = False):
        if fToStorage:
            form_str = DuplicateResolverForm.duplicate_form_text%("Export to storage","Type in storage", "Do not change type in storage","Local type in IDA","Replace by type from IDA")
        else:
            form_str = DuplicateResolverForm.duplicate_form_text%("Import from storage","Local type in IDA","Do not change local type","Type in storage","Replace by type from storage")
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
            self.selected = self.GetControlValue(self.txtMultiLineText2).text
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


class TypeListChooser(ida_kernwin.Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, type_list, flags=0, obj=None):

        Choose.__init__(self,
                         title,
                         [ ["Ord", 5], ["Name", 40] ],
                         embedded=True, width=150, height=40, flags=flags)
        self.n = 0
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selcount = 0
        self.selected = []
        self.make_items(type_list)
        self.obj = obj

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
            self.selected.append(self.items[n][1])
        #print self.selected

class TypeListChooser2(ida_kernwin.Choose):

    def __init__(self, title, type_list, flags=ida_kernwin.Choose.CH_MULTI):

        Choose.__init__(
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

        # print("created %s" % str(self))

    def OnClose(self):
        print(("closed", str(self)))

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



class TypeChooseForm(ida_kernwin.Form):
    form_text_fromIDB = """Import types from current IDB
    {FormChangeCb}
    <Types for choose:{cEChooser}>
    <##Get all types:{iButtonSyncAll}>      <Structure:{rStruct}><Enums:{rEnums}><Typedefs:{rTypedefs}>{cFilters}>
    <Resolve type dependencies:{rResDep}>
    <Show types from starndard typelibs:{rStndTypes}>{cGroup1}>
    """
    form_text_fromStorage = """Import types from storage
    {FormChangeCb}
    <Types for choose:{cEChooser}>
    <##Get all types:{iButtonSyncAll}>      <Structure:{rStruct}><Enums:{rEnums}><Typedefs:{rTypedefs}>{cFilters}>
    <Resolve type dependencies:{rResDep}>
    <Show types from starndard typelibs:{rStndTypes}>{cGroup1}>
    """

    def __init__(self,type_list, fFromIDB=True, db=None):

        self.EChooser = TypeListChooser("Types:",type_list,flags=ida_kernwin.Choose.CH_MULTI)
        self.typeList = type_list
        self.curTypes = type_list if type(type_list) == list else list(type_list.keys())
        self.fFromIDB = fFromIDB
        self.db = db
        if self.fFromIDB:
            Form.__init__(self,TypeChooseForm.form_text_fromIDB, {
                 'cEChooser' : Form.EmbeddedChooserControl(self.EChooser),
                 'iButtonSyncAll': Form.ButtonInput(self.onSyncAllTypes),
                 'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                 'cGroup1': Form.ChkGroupControl(("rResDep","rStndTypes")),
                 'cFilters': Form.ChkGroupControl(("rStruct","rEnums", "rTypedefs"))
            })
        else:
            Form.__init__(self, TypeChooseForm.form_text_fromStorage, {
                'cEChooser': Form.EmbeddedChooserControl(self.EChooser),
                'iButtonSyncAll': Form.ButtonInput(self.onSyncAllTypes),
                'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
                'cGroup1': Form.ChkGroupControl(("rResDep", "rStndTypes")),
                'cFilters': Form.ChkGroupControl(("rStruct", "rEnums", "rTypedefs"))
            })

    def Go(self):
        self.Compile()
        self.rResDep.checked = True
        # if self.fFromIDB:
        self.rStndTypes.checked = True
        self.cFilters.value = 7
        # print map(lambda x: [str(get_type_ordinal(idaapi.cvar.idati,x)),x],self.typeList.keys())
        if self.fFromIDB:
            self.EChooser.items = [[str(get_type_ordinal(idaapi.cvar.idati,x)),x] for x in list(self.typeList.keys())]
        ok = self.Execute()
        #print "Ok = %d"%ok
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

    def OnFormChange(self, fid):
        if fid == self.rStndTypes.id:
            if self.fFromIDB:
                if self.GetControlValue(self.rStndTypes):
                    self.curTypes = list(self.typeList.keys())
                else:
                    self.curTypes = []
                    for t in list(self.typeList.values()):
                        if not t.is_standard():
                            self.curTypes.append(t.name)
                self.EChooser.items = [[str(get_type_ordinal(idaapi.cvar.idati,x)), x] for x in self.curTypes]
                    # self.EChooser.make_items(["AAAA","BBBBB","FFFFFF"])
                    # self.EChooser.Embedded()
            else:
                self.curTypes = self.db.GetAllNames(self.GetControlValue(self.cFilters)|(self.GetControlValue(self.rStndTypes)<<3))
                self.EChooser.make_items(self.curTypes)
            self.RefreshField(self.controls["cEChooser"])

        if fid == self.cFilters.id:
            if self.fFromIDB:
                val = self.GetControlValue(self.cFilters)
                filtered = [x for x in self.curTypes if ((val&1 and (self.typeList[x].is_struct()or self.typeList[x].is_union())) or (val&2 and self.typeList[x].is_enum()) or (val&4 and not self.typeList[x].is_sue()))]
                self.EChooser.items = [[str(get_type_ordinal(idaapi.cvar.idati,x)), x] for x in filtered]
            else:
                # print self.GetControlValue(self.cFilters)
                # print self.GetControlValue(self.cFilters) | (self.GetControlValue(self.rStndTypes) << 3)
                self.curTypes = self.db.GetAllNames(self.GetControlValue(self.cFilters) | (self.GetControlValue(self.rStndTypes) << 3))
                # print self.curTypes
                self.EChooser.make_items(self.curTypes)
            self.RefreshField(self.controls["cEChooser"])

        return 1


class ProjectChooser(ida_kernwin.Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, name_list, db = None, flags=ida_kernwin.Choose.CH_CAN_DEL|ida_kernwin.Choose.CH_CAN_REFRESH, obj = None):

        Choose.__init__(self,
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
        #print self.items
        self.db = db
        self.obj = obj

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
        #print self.items[n]
        self.selected = self.items[n]
        self.obj.Close(1)

    def OnSelectionChange(self, sel_list):
        self.selected = []
        # print sel_list
        if type(sel_list) == int:
            self.selected.append(self.items[sel_list][0])
        else:
            for sel in sel_list:
                self.selected.append(self.items[sel][0])

    def OnDeleteLine(self, n):
        # print("del %d " % n)
        # print("del %d " % n)
        # print self.items[n]
        if fSQL:
            self.db.deleteProject(self.items[n][0])
        else:
            self.db[self.items[n][0]].drop()
        del self.items[n]
        self.obj.RefreshField(self.obj.controls["cEChooser"])
        return n




    # def OnSelectionChange(self, sel_list):
    #     self.selected = []
    #     #print sel_list
    #     for n in sel_list:
    #         self.selected.append(self.items[n-1][1])
    #     #print self.selected


class ChooseProject(ida_kernwin.Form):
    def __init__(self,coll_list,db = None):
        self.__n = 0
        self.selected = None
        self.EChooser = ProjectChooser("Projects in storage",coll_list, db, obj = self)
        self.db = db
        Form.__init__(self,
r"""
Choose project for connect
{FormChangeCb}
<Projects in storage:{cEChooser}>   <##Create new project:{iButtonNewProject}><##Delete Project:{iButtonDelProject}>
""", {
        'cEChooser' : Form.EmbeddedChooserControl(self.EChooser),
        'iButtonNewProject': Form.ButtonInput(self.onNewProject),
        'iButtonDelProject': Form.ButtonInput(self.onDelProject),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
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
        return None

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def onNewProject(self,code = 0):
        s = ida_kernwin.ask_str("", 0,"Enter new project name:")
        self.EChooser.selected = [s]
        self.Close(1)

    def onDelProject(self,code = 0):
        if len(self.EChooser.selected) > 0:
            # print self.EChooser.selected
            for sel in self.EChooser.selected:
                if fSQL:
                    self.db.deleteProject(sel)
                else:
                    self.db[sel].drop()
                self.EChooser.items.remove([sel])
            # print self.EChooser.items
            # print self.controls
            self.RefreshField(self.controls['cEChooser'])
            
    def OnFormChange(self, fid):
        if fid == self.cEChooser.id:
            self.RefreshField(self.controls["cEChooser"])
        return 1


class ConnectToSQLBase(ida_kernwin.Form):
    def __init__(self,addr):
        self.storage = None
        self.iBaseFile = None

        Form.__init__(self,r"""
        Choose path with storage

        <#Hint1#SQLite file path:{iBaseFile}>
        """, {
            'iBaseFile':Form.FileInput(open=True,hlp='*.db',value = os.path.join(find_ida_dir(),"TypeStorage.db") if addr is None else addr),
        })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        # print ("ConnectToSQLBase: Go: Ok = %d; Base file path = %s"%(ok,self.iBaseFile.value))
        if ok == 1:
            return self.iBaseFile.value
        return None



class ConnectToBase(ida_kernwin.Form):
    def __init__(self,addr):
        self.storage = None
        self.iServerIP = None
        self.iPort = None

        Form.__init__(self,r"""
        Choose server with storage

        <#Hint1#Server IP:{iServerIP}> : <#Hint1#Server port:{iPort}>
        """, {
            'iServerIP':Form.StringInput(value = "127.0.0.1" if addr is None else addr[0]),
            'iPort':Form.NumericInput(Form.FT_DEC,27017 if addr is None else addr[1]),
        })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        # print ("ConnectToBase: Go: Ok = %d; ServerIP = %s; Port = %d"%(ok,self.iServerIP.value,self.iPort.value))
        if ok == 1:
            return self.iServerIP.value, self.iPort.value
        return None
from PySide.QtCore import *
from PySide.QtGui import *
import sys
from PySide import QtCore, QtGui


class Ui_Dialog(object):
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

class TestDialog(QDialog):
    def __init__(self, parent=None):
        super(TestDialog, self).__init__(parent)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.connect(self.ui.pushButton_importStruc1, SIGNAL("clicked()"), self.testOK)
        self.connect(self.ui.pushButton_importStruc2, SIGNAL("clicked()"), self.testOK)
        self.connect(self.ui.pushButton_useMerged, SIGNAL("clicked()"), self.testOK)
        self.ui.textEdit_struc1.setText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.connect(self.ui.buttonBox,SIGNAL("accepted()"),self.testOK)
        self.connect(self.ui.buttonBox,SIGNAL("rejected()"),self.testOK)
        self.connect(self.ui.buttonBox,SIGNAL("accepted()"),self.accept)
        self.connect(self.ui.buttonBox,SIGNAL("rejected()"),self.reject)


    def testOK(self):
        print "Ok"
        print self.ui.textEdit_struc1.toPlainText()



class MyWindow(QDialog):
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)

        self.setWindowTitle("Send to CMD")

        self.check1 = QCheckBox("Activate Variable")
        self.variable = QLineEdit()
        self.finalcommand = QLineEdit()
        self.clearCommand = QPushButton("Clear")
        self.sendCommand = QPushButton("Send")
        self.clearOnSend = QCheckBox("Clear on Send")

        self.process = QProcess()
        self.console = QTextEdit(self)

        layout = QVBoxLayout()
        layout.addWidget(self.check1)
        layout.addWidget(self.variable)
        layout.addWidget(self.finalcommand)
        layout.addWidget(self.clearOnSend)
        layout.addWidget(self.clearCommand)
        layout.addWidget(self.sendCommand)
        layout.addWidget(self.console)
        self.setLayout(layout)

        self.connect(self.check1, SIGNAL("clicked()"), self.appendText)
        self.variable.textChanged.connect(self.appendText)

        self.clearCommand.clicked.connect(self.Clear)
        self.sendCommand.clicked.connect(self.Send)

    def appendText(self):
        if self.check1.isChecked():
            TEXT1 = "Dir" + ' ' + str(self.variable.text())
        else:
            TEXT1 = ""
        self.finalcommand.setText(str(TEXT1))

    def Clear(self):
        if self.clearCommand.isEnabled():
            self.console.clear()

    def Send(self):
        if self.clearOnSend.isChecked():
            self.console.clear()
        FCTS = "cmd.exe /c" + " " + str(self.finalcommand.text())
        self.process.readyReadStandardOutput.connect(self.readConsole)
        self.process.start(FCTS)
        if not self.process.waitForStarted(0):
            return False
        if not self.process.waitForFinished(0):
            return False

    def readConsole(self):
        #self.console.setText(str(self.process.readAllStandardOutput()))
        self.console.append(str(self.process.readAllStandardOutput()))

def test_show():
    global app
    form.show()
    app.exec_()

    form.show()
    app.exec_()

app = QApplication(sys.argv)
# form = MyWindow()
form = TestDialog(None)
# form.show()

form.show()
app.exec_()

form.show()
app.exec_()
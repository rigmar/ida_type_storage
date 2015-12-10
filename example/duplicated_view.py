# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'duplicated_view.ui'
#
# Created: Mon Oct 26 08:03:15 2015
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

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
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label_struc1.setText(QtGui.QApplication.translate("Dialog", "Structure 1", None, QtGui.QApplication.UnicodeUTF8))
        self.label_struc2.setText(QtGui.QApplication.translate("Dialog", "Structure 2", None, QtGui.QApplication.UnicodeUTF8))
        self.label_strucMerged.setText(QtGui.QApplication.translate("Dialog", "Merged structure", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_importStruc1.setText(QtGui.QApplication.translate("Dialog", "Import struture 1", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_importStruc2.setText(QtGui.QApplication.translate("Dialog", "Import struture 2", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton_useMerged.setText(QtGui.QApplication.translate("Dialog", "Use merged structure", None, QtGui.QApplication.UnicodeUTF8))


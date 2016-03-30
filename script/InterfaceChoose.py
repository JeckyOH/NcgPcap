# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\InterfaceChoose.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_InterfaceChooseDialog(object):
    def setupUi(self, InterfaceChooseDialog):
        InterfaceChooseDialog.setObjectName(_fromUtf8("InterfaceChooseDialog"))
        InterfaceChooseDialog.resize(901, 392)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/mainWindow_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        InterfaceChooseDialog.setWindowIcon(icon)
        self.InterfaceChooseTable = QtGui.QTableWidget(InterfaceChooseDialog)
        self.InterfaceChooseTable.setGeometry(QtCore.QRect(50, 40, 771, 192))
        self.InterfaceChooseTable.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.InterfaceChooseTable.setObjectName(_fromUtf8("InterfaceChooseTable"))
        self.InterfaceChooseTable.setColumnCount(5)
        self.InterfaceChooseTable.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.InterfaceChooseTable.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.InterfaceChooseTable.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.InterfaceChooseTable.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.InterfaceChooseTable.setHorizontalHeaderItem(3, item)
        item = QtGui.QTableWidgetItem()
        self.InterfaceChooseTable.setHorizontalHeaderItem(4, item)
        self.InterfaceChooseTable.horizontalHeader().setDefaultSectionSize(150)
        self.layoutWidget = QtGui.QWidget(InterfaceChooseDialog)
        self.layoutWidget.setGeometry(QtCore.QRect(210, 254, 421, 51))
        self.layoutWidget.setObjectName(_fromUtf8("layoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.OKBtn = QtGui.QPushButton(self.layoutWidget)
        self.OKBtn.setObjectName(_fromUtf8("OKBtn"))
        self.horizontalLayout.addWidget(self.OKBtn)
        self.NoBtn = QtGui.QPushButton(self.layoutWidget)
        self.NoBtn.setObjectName(_fromUtf8("NoBtn"))
        self.horizontalLayout.addWidget(self.NoBtn)

        self.retranslateUi(InterfaceChooseDialog)
        QtCore.QMetaObject.connectSlotsByName(InterfaceChooseDialog)

    def retranslateUi(self, InterfaceChooseDialog):
        InterfaceChooseDialog.setWindowTitle(_translate("InterfaceChooseDialog", "InterfaceChoose", None))
        item = self.InterfaceChooseTable.horizontalHeaderItem(0)
        item.setText(_translate("InterfaceChooseDialog", "抓取", None))
        item = self.InterfaceChooseTable.horizontalHeaderItem(1)
        item.setText(_translate("InterfaceChooseDialog", "IP地址", None))
        item = self.InterfaceChooseTable.horizontalHeaderItem(2)
        item.setText(_translate("InterfaceChooseDialog", "名称", None))
        item = self.InterfaceChooseTable.horizontalHeaderItem(3)
        item.setText(_translate("InterfaceChooseDialog", "简介", None))
        item = self.InterfaceChooseTable.horizontalHeaderItem(4)
        item.setText(_translate("InterfaceChooseDialog", "子网掩码", None))
        self.OKBtn.setText(_translate("InterfaceChooseDialog", "确定", None))
        self.NoBtn.setText(_translate("InterfaceChooseDialog", "取消", None))


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    InterfaceChooseDialog = QtGui.QDialog()
    ui = Ui_InterfaceChooseDialog()
    ui.setupUi(InterfaceChooseDialog)
    InterfaceChooseDialog.show()
    sys.exit(app.exec_())


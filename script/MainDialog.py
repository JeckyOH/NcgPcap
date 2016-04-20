# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\MainDialog.ui'
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

class Ui_NcgPcapDialog(object):
    def setupUi(self, NcgPcapDialog):
        NcgPcapDialog.setObjectName(_fromUtf8("NcgPcapDialog"))
        NcgPcapDialog.resize(1045, 847)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/mainWindow_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        NcgPcapDialog.setWindowIcon(icon)
        self.tabWidget = QtGui.QTabWidget(NcgPcapDialog)
        self.tabWidget.setGeometry(QtCore.QRect(20, 20, 1001, 811))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.tabWidget.setFont(font)
        self.tabWidget.setAccessibleName(_fromUtf8(""))
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.NcgTab = QtGui.QWidget()
        self.NcgTab.setObjectName(_fromUtf8("NcgTab"))
        self.LogConfGroupBox = QtGui.QGroupBox(self.NcgTab)
        self.LogConfGroupBox.setGeometry(QtCore.QRect(30, 10, 871, 101))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.LogConfGroupBox.setFont(font)
        self.LogConfGroupBox.setObjectName(_fromUtf8("LogConfGroupBox"))
        self.layoutWidget = QtGui.QWidget(self.LogConfGroupBox)
        self.layoutWidget.setGeometry(QtCore.QRect(30, 50, 711, 41))
        self.layoutWidget.setObjectName(_fromUtf8("layoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.LogPathStatic = QtGui.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.LogPathStatic.setFont(font)
        self.LogPathStatic.setObjectName(_fromUtf8("LogPathStatic"))
        self.horizontalLayout.addWidget(self.LogPathStatic)
        self.LogPathEdit = QtGui.QLineEdit(self.layoutWidget)
        self.LogPathEdit.setReadOnly(True)
        self.LogPathEdit.setObjectName(_fromUtf8("LogPathEdit"))
        self.horizontalLayout.addWidget(self.LogPathEdit)
        self.LogPathScanBtn = QtGui.QPushButton(self.layoutWidget)
        self.LogPathScanBtn.setObjectName(_fromUtf8("LogPathScanBtn"))
        self.horizontalLayout.addWidget(self.LogPathScanBtn)
        self.widget = QtGui.QWidget(self.LogConfGroupBox)
        self.widget.setGeometry(QtCore.QRect(30, 18, 321, 31))
        self.widget.setObjectName(_fromUtf8("widget"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.widget)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.NewestLogRadioBtn = QtGui.QRadioButton(self.widget)
        self.NewestLogRadioBtn.setObjectName(_fromUtf8("NewestLogRadioBtn"))
        self.horizontalLayout_2.addWidget(self.NewestLogRadioBtn)
        self.AllLogRadioBtn = QtGui.QRadioButton(self.widget)
        self.AllLogRadioBtn.setObjectName(_fromUtf8("AllLogRadioBtn"))
        self.horizontalLayout_2.addWidget(self.AllLogRadioBtn)
        self.PCapGroupBox = QtGui.QGroupBox(self.NcgTab)
        self.PCapGroupBox.setGeometry(QtCore.QRect(30, 120, 871, 571))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.PCapGroupBox.setFont(font)
        self.PCapGroupBox.setObjectName(_fromUtf8("PCapGroupBox"))
        self.LocalComtGroupBox = QtGui.QGroupBox(self.PCapGroupBox)
        self.LocalComtGroupBox.setGeometry(QtCore.QRect(20, 90, 831, 221))
        self.LocalComtGroupBox.setObjectName(_fromUtf8("LocalComtGroupBox"))
        self.layoutWidget1 = QtGui.QWidget(self.LocalComtGroupBox)
        self.layoutWidget1.setGeometry(QtCore.QRect(17, 23, 391, 191))
        self.layoutWidget1.setObjectName(_fromUtf8("layoutWidget1"))
        self.gridLayout = QtGui.QGridLayout(self.layoutWidget1)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.LocalIpStatic = QtGui.QLabel(self.layoutWidget1)
        self.LocalIpStatic.setObjectName(_fromUtf8("LocalIpStatic"))
        self.horizontalLayout_5.addWidget(self.LocalIpStatic)
        self.InterfaceChooseBtn = QtGui.QPushButton(self.layoutWidget1)
        self.InterfaceChooseBtn.setObjectName(_fromUtf8("InterfaceChooseBtn"))
        self.horizontalLayout_5.addWidget(self.InterfaceChooseBtn)
        self.gridLayout.addLayout(self.horizontalLayout_5, 0, 0, 1, 1)
        self.cascInterfaceShowEdit = QtGui.QTextEdit(self.layoutWidget1)
        self.cascInterfaceShowEdit.setObjectName(_fromUtf8("cascInterfaceShowEdit"))
        self.gridLayout.addWidget(self.cascInterfaceShowEdit, 1, 0, 1, 1)
        self.layoutWidget2 = QtGui.QWidget(self.LocalComtGroupBox)
        self.layoutWidget2.setGeometry(QtCore.QRect(440, 20, 371, 191))
        self.layoutWidget2.setObjectName(_fromUtf8("layoutWidget2"))
        self.gridLayout_4 = QtGui.QGridLayout(self.layoutWidget2)
        self.gridLayout_4.setObjectName(_fromUtf8("gridLayout_4"))
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.SipPortStatic = QtGui.QLabel(self.layoutWidget2)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.SipPortStatic.setFont(font)
        self.SipPortStatic.setObjectName(_fromUtf8("SipPortStatic"))
        self.horizontalLayout_4.addWidget(self.SipPortStatic)
        self.SipPortEdit = QtGui.QLineEdit(self.layoutWidget2)
        self.SipPortEdit.setReadOnly(True)
        self.SipPortEdit.setObjectName(_fromUtf8("SipPortEdit"))
        self.horizontalLayout_4.addWidget(self.SipPortEdit)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.PrivatePortStatic = QtGui.QLabel(self.layoutWidget2)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.PrivatePortStatic.setFont(font)
        self.PrivatePortStatic.setObjectName(_fromUtf8("PrivatePortStatic"))
        self.horizontalLayout_3.addWidget(self.PrivatePortStatic)
        self.PrivatePortEdit = QtGui.QLineEdit(self.layoutWidget2)
        self.PrivatePortEdit.setReadOnly(True)
        self.PrivatePortEdit.setObjectName(_fromUtf8("PrivatePortEdit"))
        self.horizontalLayout_3.addWidget(self.PrivatePortEdit)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.gridLayout_4.addLayout(self.verticalLayout, 0, 0, 1, 1)
        self.gridLayout_3 = QtGui.QGridLayout()
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.PortablePortList = QtGui.QListWidget(self.layoutWidget2)
        self.PortablePortList.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.PortablePortList.setEditTriggers(QtGui.QAbstractItemView.CurrentChanged|QtGui.QAbstractItemView.DoubleClicked|QtGui.QAbstractItemView.EditKeyPressed|QtGui.QAbstractItemView.SelectedClicked)
        self.PortablePortList.setObjectName(_fromUtf8("PortablePortList"))
        self.gridLayout_3.addWidget(self.PortablePortList, 0, 1, 2, 1)
        self.AddPortablePortBtn = QtGui.QPushButton(self.layoutWidget2)
        self.AddPortablePortBtn.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/add_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.AddPortablePortBtn.setIcon(icon1)
        self.AddPortablePortBtn.setObjectName(_fromUtf8("AddPortablePortBtn"))
        self.gridLayout_3.addWidget(self.AddPortablePortBtn, 0, 2, 1, 1)
        self.DelPortablePortBtn = QtGui.QPushButton(self.layoutWidget2)
        self.DelPortablePortBtn.setText(_fromUtf8(""))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/delete_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.DelPortablePortBtn.setIcon(icon2)
        self.DelPortablePortBtn.setObjectName(_fromUtf8("DelPortablePortBtn"))
        self.gridLayout_3.addWidget(self.DelPortablePortBtn, 1, 2, 1, 1)
        self.PortablePortStatic = QtGui.QLabel(self.layoutWidget2)
        self.PortablePortStatic.setObjectName(_fromUtf8("PortablePortStatic"))
        self.gridLayout_3.addWidget(self.PortablePortStatic, 0, 0, 2, 1)
        self.gridLayout_4.addLayout(self.gridLayout_3, 1, 0, 1, 1)
        self.MediaGroupBox = QtGui.QGroupBox(self.PCapGroupBox)
        self.MediaGroupBox.setGeometry(QtCore.QRect(20, 320, 831, 171))
        self.MediaGroupBox.setObjectName(_fromUtf8("MediaGroupBox"))
        self.MediaTable = QtGui.QTableWidget(self.MediaGroupBox)
        self.MediaTable.setGeometry(QtCore.QRect(20, 30, 731, 121))
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.MediaTable.setFont(font)
        self.MediaTable.setMidLineWidth(0)
        self.MediaTable.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.MediaTable.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.MediaTable.setObjectName(_fromUtf8("MediaTable"))
        self.MediaTable.setColumnCount(9)
        self.MediaTable.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(3, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(4, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(5, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(6, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(7, item)
        item = QtGui.QTableWidgetItem()
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        item.setFont(font)
        self.MediaTable.setHorizontalHeaderItem(8, item)
        self.MediaTable.horizontalHeader().setDefaultSectionSize(150)
        self.layoutWidget3 = QtGui.QWidget(self.MediaGroupBox)
        self.layoutWidget3.setGeometry(QtCore.QRect(759, 30, 51, 121))
        self.layoutWidget3.setObjectName(_fromUtf8("layoutWidget3"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.layoutWidget3)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.AddMediaBtn = QtGui.QPushButton(self.layoutWidget3)
        self.AddMediaBtn.setText(_fromUtf8(""))
        self.AddMediaBtn.setIcon(icon1)
        self.AddMediaBtn.setObjectName(_fromUtf8("AddMediaBtn"))
        self.verticalLayout_3.addWidget(self.AddMediaBtn)
        self.ModMediaBtn = QtGui.QPushButton(self.layoutWidget3)
        self.ModMediaBtn.setText(_fromUtf8(""))
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/mod_media.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.ModMediaBtn.setIcon(icon3)
        self.ModMediaBtn.setObjectName(_fromUtf8("ModMediaBtn"))
        self.verticalLayout_3.addWidget(self.ModMediaBtn)
        self.DelMediaBtn = QtGui.QPushButton(self.layoutWidget3)
        self.DelMediaBtn.setText(_fromUtf8(""))
        self.DelMediaBtn.setIcon(icon2)
        self.DelMediaBtn.setObjectName(_fromUtf8("DelMediaBtn"))
        self.verticalLayout_3.addWidget(self.DelMediaBtn)
        self.layoutWidget4 = QtGui.QWidget(self.PCapGroupBox)
        self.layoutWidget4.setGeometry(QtCore.QRect(20, 20, 331, 61))
        self.layoutWidget4.setObjectName(_fromUtf8("layoutWidget4"))
        self.gridLayout_2 = QtGui.QGridLayout(self.layoutWidget4)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.specificCapCheckBox = QtGui.QCheckBox(self.layoutWidget4)
        self.specificCapCheckBox.setObjectName(_fromUtf8("specificCapCheckBox"))
        self.gridLayout_2.addWidget(self.specificCapCheckBox, 0, 0, 1, 2)
        self.OthIpStatic = QtGui.QLabel(self.layoutWidget4)
        self.OthIpStatic.setObjectName(_fromUtf8("OthIpStatic"))
        self.gridLayout_2.addWidget(self.OthIpStatic, 1, 0, 1, 1)
        self.OthIpEdit = QtGui.QLineEdit(self.layoutWidget4)
        self.OthIpEdit.setObjectName(_fromUtf8("OthIpEdit"))
        self.gridLayout_2.addWidget(self.OthIpEdit, 1, 1, 1, 1)
        self.layoutWidget5 = QtGui.QWidget(self.PCapGroupBox)
        self.layoutWidget5.setGeometry(QtCore.QRect(190, 500, 461, 41))
        self.layoutWidget5.setObjectName(_fromUtf8("layoutWidget5"))
        self.gridLayout_5 = QtGui.QGridLayout(self.layoutWidget5)
        self.gridLayout_5.setSpacing(150)
        self.gridLayout_5.setObjectName(_fromUtf8("gridLayout_5"))
        self.StartCapBtn = QtGui.QPushButton(self.layoutWidget5)
        self.StartCapBtn.setObjectName(_fromUtf8("StartCapBtn"))
        self.gridLayout_5.addWidget(self.StartCapBtn, 0, 0, 1, 1)
        self.StopCapBtn = QtGui.QPushButton(self.layoutWidget5)
        self.StopCapBtn.setObjectName(_fromUtf8("StopCapBtn"))
        self.gridLayout_5.addWidget(self.StopCapBtn, 0, 1, 1, 1)
        self.layoutWidget6 = QtGui.QWidget(self.NcgTab)
        self.layoutWidget6.setGeometry(QtCore.QRect(60, 710, 741, 41))
        self.layoutWidget6.setObjectName(_fromUtf8("layoutWidget6"))
        self.horizontalLayout_6 = QtGui.QHBoxLayout(self.layoutWidget6)
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.AllCompressedPath = QtGui.QLabel(self.layoutWidget6)
        self.AllCompressedPath.setObjectName(_fromUtf8("AllCompressedPath"))
        self.horizontalLayout_6.addWidget(self.AllCompressedPath)
        self.AllCompressedPathEdit = QtGui.QLineEdit(self.layoutWidget6)
        self.AllCompressedPathEdit.setReadOnly(True)
        self.AllCompressedPathEdit.setObjectName(_fromUtf8("AllCompressedPathEdit"))
        self.horizontalLayout_6.addWidget(self.AllCompressedPathEdit)
        self.AllCompressedPathScanBtn = QtGui.QPushButton(self.layoutWidget6)
        self.AllCompressedPathScanBtn.setObjectName(_fromUtf8("AllCompressedPathScanBtn"))
        self.horizontalLayout_6.addWidget(self.AllCompressedPathScanBtn)
        self.CompressBtn = QtGui.QPushButton(self.layoutWidget6)
        self.CompressBtn.setObjectName(_fromUtf8("CompressBtn"))
        self.horizontalLayout_6.addWidget(self.CompressBtn)
        self.tabWidget.addTab(self.NcgTab, _fromUtf8(""))
        self.OthersTab = QtGui.QWidget()
        self.OthersTab.setObjectName(_fromUtf8("OthersTab"))
        self.tabWidget.addTab(self.OthersTab, _fromUtf8(""))
        self.actionOpenFile = QtGui.QAction(NcgPcapDialog)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8("rsc/icon/open_file.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionOpenFile.setIcon(icon4)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Consolas"))
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.actionOpenFile.setFont(font)
        self.actionOpenFile.setObjectName(_fromUtf8("actionOpenFile"))

        self.retranslateUi(NcgPcapDialog)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(NcgPcapDialog)

    def retranslateUi(self, NcgPcapDialog):
        NcgPcapDialog.setWindowTitle(_translate("NcgPcapDialog", "NcgPcap", None))
        self.NcgTab.setAccessibleName(_translate("NcgPcapDialog", "NCG", None))
        self.LogConfGroupBox.setTitle(_translate("NcgPcapDialog", "日志打包配置", None))
        self.LogPathStatic.setText(_translate("NcgPcapDialog", "日志文件路径：", None))
        self.LogPathScanBtn.setText(_translate("NcgPcapDialog", "浏览", None))
        self.NewestLogRadioBtn.setText(_translate("NcgPcapDialog", "最新日志", None))
        self.AllLogRadioBtn.setText(_translate("NcgPcapDialog", "全部日志", None))
        self.PCapGroupBox.setTitle(_translate("NcgPcapDialog", "抓包配置", None))
        self.LocalComtGroupBox.setTitle(_translate("NcgPcapDialog", "本机信令网关服务器配置", None))
        self.LocalIpStatic.setText(_translate("NcgPcapDialog", "IP地址：", None))
        self.InterfaceChooseBtn.setText(_translate("NcgPcapDialog", "选择网络适配器", None))
        self.cascInterfaceShowEdit.setHtml(_translate("NcgPcapDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Consolas\'; font-size:10pt; font-weight:600; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>", None))
        self.SipPortStatic.setText(_translate("NcgPcapDialog", "SIP端口:", None))
        self.PrivatePortStatic.setText(_translate("NcgPcapDialog", "客户端端口：", None))
        self.PortablePortStatic.setText(_translate("NcgPcapDialog", "自定义扩展端口：", None))
        self.MediaGroupBox.setTitle(_translate("NcgPcapDialog", "本级媒体网关服务器配置", None))
        item = self.MediaTable.horizontalHeaderItem(0)
        item.setText(_translate("NcgPcapDialog", "IP地址", None))
        item = self.MediaTable.horizontalHeaderItem(1)
        item.setText(_translate("NcgPcapDialog", "抓包网卡数", None))
        item = self.MediaTable.horizontalHeaderItem(2)
        item.setText(_translate("NcgPcapDialog", "RTSP端口", None))
        item = self.MediaTable.horizontalHeaderItem(3)
        item.setText(_translate("NcgPcapDialog", "UDP传输开始端口", None))
        item = self.MediaTable.horizontalHeaderItem(4)
        item.setText(_translate("NcgPcapDialog", "UDP传输端口数目", None))
        item = self.MediaTable.horizontalHeaderItem(5)
        item.setText(_translate("NcgPcapDialog", "RTSP接收端口Base", None))
        item = self.MediaTable.horizontalHeaderItem(6)
        item.setText(_translate("NcgPcapDialog", "RTSP接收端口数目", None))
        item = self.MediaTable.horizontalHeaderItem(7)
        item.setText(_translate("NcgPcapDialog", "RTSP发送端口Base", None))
        item = self.MediaTable.horizontalHeaderItem(8)
        item.setText(_translate("NcgPcapDialog", "RTSP发送端口数目", None))
        self.AddMediaBtn.setToolTip(_translate("NcgPcapDialog", "<html><head/><body><p>添加媒体网关配置项</p></body></html>", None))
        self.ModMediaBtn.setToolTip(_translate("NcgPcapDialog", "修改选中的媒体网关信息", None))
        self.DelMediaBtn.setToolTip(_translate("NcgPcapDialog", "<html><head/><body><p>删除媒体网关配置项</p></body></html>", None))
        self.specificCapCheckBox.setText(_translate("NcgPcapDialog", "抓取指定对端的包", None))
        self.OthIpStatic.setText(_translate("NcgPcapDialog", "对端IP地址：", None))
        self.StartCapBtn.setText(_translate("NcgPcapDialog", "开始抓包", None))
        self.StopCapBtn.setText(_translate("NcgPcapDialog", "停止抓包", None))
        self.AllCompressedPath.setText(_translate("NcgPcapDialog", "打包路径：", None))
        self.AllCompressedPathScanBtn.setText(_translate("NcgPcapDialog", "浏览", None))
        self.CompressBtn.setText(_translate("NcgPcapDialog", "打包", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.NcgTab), _translate("NcgPcapDialog", "NCG", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.OthersTab), _translate("NcgPcapDialog", "Others", None))
        self.actionOpenFile.setText(_translate("NcgPcapDialog", "OpenFile", None))
        self.actionOpenFile.setToolTip(_translate("NcgPcapDialog", "打开文件", None))


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    NcgPcapDialog = QtGui.QDialog()
    ui = Ui_NcgPcapDialog()
    ui.setupUi(NcgPcapDialog)
    NcgPcapDialog.show()
    sys.exit(app.exec_())


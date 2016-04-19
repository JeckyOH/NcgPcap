# -*- coding: utf-8 -*-

from InterfaceChoose import *
import GlobalVar as GLV
from WrapperNpcapDll import *
import ctypes

class IfChooseWindow(Ui_InterfaceChooseDialog):
	def setupUi(self, InterfaceChooseDialog, ifList = None):
		super(IfChooseWindow,self).setupUi(InterfaceChooseDialog)
		""" 绑定OK按钮单击槽 """
		self.dialog.connect(self.OKBtn,QtCore.SIGNAL('clicked()'),self.on_OKBtn_Clicked)
		""" 绑定取消按钮单击槽 """
		self.dialog.connect(self.NoBtn,QtCore.SIGNAL('clicked()'),self.on_NOBtn_Clicked)

		""" 获取网络设备接口并显示 """
		if ifList != None:
			""" 增加表格中网络设备节点 """
			row = 0
			#for cap_if in WrapperNpcapDll.npcap_if_iterator(ifList):
			cap_if = ifList
			while bool(cap_if) == True:
				self.InterfaceChooseTable.insertRow(self.InterfaceChooseTable.rowCount())
				ifCheckBox = QtGui.QCheckBox()
				self.InterfaceChooseTable.setCellWidget(row,0,ifCheckBox)
				self.InterfaceChooseTable.cellWidget(row,0).setChecked(True)
				item = QtGui.QTableWidgetItem(cap_if.contents.ip)
				item.setTextAlignment(QtCore.Qt.AlignCenter)
				self.InterfaceChooseTable.setItem(row,1,item)
				item = QtGui.QTableWidgetItem(cap_if.contents.name)
				item.setTextAlignment(QtCore.Qt.AlignCenter)
				self.InterfaceChooseTable.setItem(row,2,item)
				item = QtGui.QTableWidgetItem(cap_if.contents.description)
				item.setTextAlignment(QtCore.Qt.AlignCenter)
				self.InterfaceChooseTable.setItem(row,3,item)
				item = QtGui.QTableWidgetItem(cap_if.contents.netmask)
				item.setTextAlignment(QtCore.Qt.AlignCenter)
				self.InterfaceChooseTable.setItem(row,4,item)
				cap_if = cap_if.contents.next
				row = row + 1

	""" OK按钮的单击槽 """
	@QtCore.pyqtSlot()
	def on_OKBtn_Clicked(self):
		for row in range(self.InterfaceChooseTable.rowCount()):
			if self.InterfaceChooseTable.cellWidget(row,0).isChecked() == True:
				interfaceItem = GLV.DeviceItem()
				interfaceItem.name = str(self.InterfaceChooseTable.item(row,2).text())
				interfaceItem.ip = str(self.InterfaceChooseTable.item(row,1).text())
				interfaceItem.netmask = str(self.InterfaceChooseTable.item(row,4).text())
				self.interfaceList.append(interfaceItem)
		self.dialog.accept()

	""" CANSEL按钮的单击槽 """
	@QtCore.pyqtSlot()
	def on_NOBtn_Clicked(self):
		del self.interfaceList[:]
		self.dialog.reject()

	def show_window(self, ifList = None):
		self.dialog = QtGui.QDialog()
		self.interfaceList = []
		self.setupUi(self.dialog, ifList)
		return (self.dialog.exec_(),self.interfaceList)

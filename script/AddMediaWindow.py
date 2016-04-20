# -*- coding: utf-8 -*-

from AddMediaDialog import *
import GlobalVar as GLV
import IfChooseWindow as IfChooseModule
from WrapperNpcapDll import *

import ctypes

class AddMediaWindow(Ui_AddMediaDialog):
	def setupUi(self, AddMediaDialog):
		super(AddMediaWindow,self).setupUi(AddMediaDialog)
		""" 绑定选择网络适配器按钮的单击槽 """
		self.dialog.connect(self.ChooseInterfaceBtn,QtCore.SIGNAL('clicked()'),self.on_ChooseInterfaceBtn_Clicked)

		""" 把日志模式的选择radio按钮放到一个buttonGroup里面，然后绑定上同一个单击槽 """
		self.mediaPosRadioBtnGroup = QtGui.QButtonGroup()
		self.mediaPosRadioBtnGroup.addButton(self.RemoteMediaRadioBtn,1)
		self.mediaPosRadioBtnGroup.addButton(self.LocalMediaRadioBtn,0)
		self.dialog.connect(self.RemoteMediaRadioBtn,QtCore.SIGNAL('clicked()'),self.on_mediaPosRadioBtnGroup_Clicked)
		self.dialog.connect(self.LocalMediaRadioBtn,QtCore.SIGNAL('clicked()'),self.on_mediaPosRadioBtnGroup_Clicked)

		""" 绑定确认和取消按钮的单击槽 """
		self.dialog.connect(self.OkBtn,QtCore.SIGNAL('clicked()'),self.on_OkBtn_Clicked)
		self.dialog.connect(self.NoBtn,QtCore.SIGNAL('clicked()'),self.on_NoBtn_Clicked)

	@QtCore.pyqtSlot()
	def on_mediaPosRadioBtnGroup_Clicked(self):
		""" 媒体网关位置：远程媒体网关/本地媒体网关 的radio按钮的单击事件槽 """
		self.media.mediaPosition = self.mediaPosRadioBtnGroup.checkedId() #这里的RadioButton的ID和各模式的值已经设置为对应的，所以直接赋值即可
		if self.media.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
			self.RemoteCapIpEdit.clear()
			self.RemoteCapIpEdit.setEnabled(False)
			self.RemoteCapPortEdit.clear()
			self.RemoteCapPortEdit.setEnabled(False)
			self.RmtUsrNameEdit.clear()
			self.RmtUsrNameEdit.setEnabled(False)
			self.RmtPwdEdit.clear()
			self.RmtPwdEdit.setEnabled(False)
		else:
			self.RemoteCapIpEdit.clear()
			self.RemoteCapIpEdit.setEnabled(True)
			self.RemoteCapPortEdit.clear()
			self.RemoteCapPortEdit.setEnabled(True)
			self.RemoteCapPortEdit.setText('2002')
			self.RmtUsrNameEdit.clear()
			self.RmtUsrNameEdit.setEnabled(True)
			self.RmtPwdEdit.clear()
			self.RmtPwdEdit.setEnabled(True)

	@QtCore.pyqtSlot()
	def on_ChooseInterfaceBtn_Clicked(self):
		""" 选择网络适配器按钮的单击槽 """
		errbuf = ctypes.create_string_buffer(NPCAP_ERROR_BUFF_SIZE)
		ifList = ctypes.POINTER(npcap_if_t)()
		if self.media.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
			pcIp = None
			pcPort = c_int(0)
			pcUsrName = None
			pcPwd = None
		else:
			pcIp = c_char_p(str(self.RemoteCapIpEdit.text()))
			pcPort = c_int(int(str(self.RemoteCapPortEdit.text())))
			pcUsrName = c_char_p(str(self.RmtUsrNameEdit.text()))
			pcPwd = c_char_p(str(self.RmtPwdEdit.text()))
		if npcap_findalldevs(c_int(self.media.mediaPosition),pcIp, pcPort, pcUsrName, pcPwd, ctypes.byref(ifList), errbuf) == NPCAP_ERROR:
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("获取网络设备接口错误：")+ errbuf.value)
			return
		IfChooseWin = IfChooseModule.IfChooseWindow()
		result, interfaceListTmp = IfChooseWin.show_window(ifList)
		npcap_freealldevs(ifList)
		if result == QtGui.QDialog.Rejected:
			return
		self.media.netIfList = interfaceListTmp[:]
		self.InterfaceChoseDisplayText.clear()
		for item in self.media.netIfList:
			self.InterfaceChoseDisplayText.append(item.ip)
		if self.media.mediaPosition == GLV.NPCAP_MEDIA_REMOTE:
			remoteInfo = GLV.RemotePc()
			remoteInfo.ip = str(self.RemoteCapIpEdit.text())
			remoteInfo.port = str(self.RemoteCapPortEdit.text())
			remoteInfo.usrName = str(self.RmtUsrNameEdit.text())
			remoteInfo.pwd = str(self.RmtPwdEdit.text())
			self.media.setRemote(remoteInfo)

	@QtCore.pyqtSlot()
	def on_OkBtn_Clicked(self):
		""" 确认按钮的单击槽 """
		if len(self.media.netIfList) == 0:
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("请选择网络适配器！"))
			return
		self.media.rtspPort = str(self.RtspPortEdit.text())
		self.media.udpPortBase = str(self.UdpPortBaseEdit.text())
		self.media.udpPortNum = str(self.UdpPortNumEdit.text())
		self.media.rtspSendPortBase = str(self.RtspSendPortBaseEdit.text())
		self.media.rtspSendPortNum = str(self.RtspSendPortNumEdit.text())
		self.media.rtspRecvPortBase = str(self.RtspRecvPortBaseEdit.text())
		self.media.rtspRecvPortNum = str(self.RtspRecvPortNumEdit.text())
		self.dialog.accept()


	@QtCore.pyqtSlot()
	def on_NoBtn_Clicked(self):
		""" 取消按钮的单击槽 """
		self.dialog.reject()


	def initWidgetText(self):
		""" 初始化窗口时显示类成员media的成员值到窗口控件 """
		self.RtspPortEdit.setText(self.media.rtspPort)
		self.UdpPortBaseEdit.setText(self.media.udpPortBase)
		self.UdpPortNumEdit.setText(self.media.udpPortNum)
		self.RtspSendPortBaseEdit.setText(self.media.rtspSendPortBase)
		self.RtspSendPortNumEdit.setText(self.media.rtspSendPortNum)
		self.RtspRecvPortBaseEdit.setText(self.media.rtspRecvPortBase)
		self.RtspRecvPortNumEdit.setText(self.media.rtspRecvPortNum)
		self.mediaPosRadioBtnGroup.button(self.media.mediaPosition).setChecked(True)
		if self.media.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
			self.RemoteCapIpEdit.setEnabled(False)
			self.RemoteCapPortEdit.setEnabled(False)
			self.RmtUsrNameEdit.setEnabled(False)
			self.RmtPwdEdit.setEnabled(False)
		else:
			self.RemoteCapIpEdit.setText(self.media.remoteInfo.ip)
			self.RemoteCapPortEdit.setText(self.media.remoteInfo.port)
			self.RmtUsrNameEdit.setText(self.media.remoteInfo.usrName)
			self.RmtPwdEdit.setText(self.media.remoteInfo.pwd)
		for interface in self.media.netIfList:
			self.InterfaceChoseDisplayText.append(interface.ip)

	def show_add_window(self):
		""" 显示增加媒体网关界面 """
		self.media = GLV.Media()
		self.dialog = QtGui.QDialog()
		self.setupUi(self.dialog)
		
		self.initWidgetText()
		return (self.dialog.exec_(),self.media)

	def show_mod_window(self,index):
		""" 显示修改媒体网关页面 """
		self.media = GLV.mediaList[index]
		self.dialog = QtGui.QDialog()
		self.setupUi(self.dialog)
		
		self.initWidgetText()
		return (self.dialog.exec_(),self.media)
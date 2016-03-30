# -*- coding: utf-8 -*-

from MainDialog import *
import IfChooseWindow as IfChooseModule
import AddMediaWindow as AddMediaModule

import GlobalVar as GLV
from WrapperNpcapDll import *
import ctypes

import os
import time
try:
	import xml.etree.cElementTree as ET
except ImportError:
	import xml.etree.ElementTree as ET


""" 继承一下UI界面，执行一些自定义过程 """
class NcgPcapMainWindow(Ui_NcgPcapDialog):
	HAVE_LOCAL_MEDIA = False

	def show_window(self):
		self.dialog = QtGui.QDialog() #将对话框类对象作为此类的成员变量
		self.setupUi(self.dialog)
		self.dialog.show()
		return

	def setupUi(self, NcgPcapDialog):
		#self.dialog = NcgPcapDialog #保存对话框成成员变量先
		super(NcgPcapMainWindow,self).setupUi(NcgPcapDialog)

		""" 在子类重新设置窗口中的图标,防止因为父类用designer重新生成后图标路径改变导致的图标加载不成功 """
		iconAddPort = QtGui.QIcon() #增加扩展端口
		iconAddPort.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/add_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.AddPortablePortBtn.setIcon(iconAddPort)

		iconDelPort = QtGui.QIcon() #删除扩展端口
		iconDelPort.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/delete_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.DelPortablePortBtn.setIcon(iconDelPort)

		iconPro = QtGui.QIcon() #程序图标
		iconPro.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/mainWindow_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		NcgPcapDialog.setWindowIcon(iconPro)

		iconAddMedia = QtGui.QIcon() #增加媒体网关图标
		iconAddMedia.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/add_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.AddMediaBtn.setIcon(iconAddMedia)

		iconModMedia = QtGui.QIcon() #修改媒体网关图标
		iconModMedia.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/mod_media.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.ModMediaBtn.setIcon(iconModMedia)

		iconDelMedia = QtGui.QIcon() #删除媒体网关图标
		iconDelMedia.addPixmap(QtGui.QPixmap(QtCore.QString.fromUtf8("../ui/rsc/icon/delete_media_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.DelMediaBtn.setIcon(iconDelMedia)

		""" 把日志模式的选择radio按钮放到一个buttonGroup里面，然后绑定上同一个单击槽 """
		self.logModRadioBtnGroup = QtGui.QButtonGroup()
		self.logModRadioBtnGroup.addButton(self.NewestLogRadioBtn,0)
		self.logModRadioBtnGroup.addButton(self.AllLogRadioBtn,1)
		NcgPcapDialog.connect(self.NewestLogRadioBtn,QtCore.SIGNAL('clicked()'),self.on_LogModRadioBtnGroup_Clicked)
		NcgPcapDialog.connect(self.AllLogRadioBtn,QtCore.SIGNAL('clicked()'),self.on_LogModRadioBtnGroup_Clicked)

		""" 绑定抓取指定对端的复选框的单击槽 """
		NcgPcapDialog.connect(self.specificCapCheckBox,QtCore.SIGNAL("clicked()"),self.on_specificCapCheckBox_Clicked)

		""" 绑定对端IP编辑框的编辑槽 """
		NcgPcapDialog.connect(self.OthIpEdit,QtCore.SIGNAL('textEdited(QString)'),self.on_OthIpEdit_textEdit)

		""" 绑定日志路径的“浏览”按钮的信号槽 """
		NcgPcapDialog.connect(self.LogPathScanBtn,QtCore.SIGNAL("clicked()"),self.on_LogPathScanBtn_Clicked)

		""" 绑定添加扩展端口按钮的单击槽 """
		NcgPcapDialog.connect(self.AddPortablePortBtn,QtCore.SIGNAL('clicked()'),self.on_AddPortablePortBtn_Clicked)

		""" 绑定删除扩展端口按钮的单击槽 """
		NcgPcapDialog.connect(self.DelPortablePortBtn,QtCore.SIGNAL('clicked()'),self.on_DelPortablePortBtn_Clicked)

		""" 绑定扩展端口列表的双击槽 """
		NcgPcapDialog.connect(self.PortablePortList,QtCore.SIGNAL('itemDoubleClicked(QListWidgetItem*)'),self.on_PortablePortList_doubleClicked)
		""" 绑定扩展端口列表的选中转移槽 """
		NcgPcapDialog.connect(self.PortablePortList,QtCore.SIGNAL('currentItemChanged(QListWidgetItem*,QListWidgetItem*)'),self.on_PortablePortList_curItemChange)
		""" 绑定扩展端口列表的变化槽 """
		NcgPcapDialog.connect(self.PortablePortList,QtCore.SIGNAL('itemChanged(QListWidgetItem*)'),self.on_PortablePortList_itemChanged)

		""" 绑定选择网络适配器按钮的单击槽 """
		NcgPcapDialog.connect(self.InterfaceChooseBtn,QtCore.SIGNAL('clicked()'),self.on_InterfaceChooseBtn_Clicked)

		""" 绑定增加媒体网关按钮的单击槽 """
		NcgPcapDialog.connect(self.AddMediaBtn,QtCore.SIGNAL('clicked()'),self.on_AddMediaBtn_Clicked)

		""" 绑定修改媒体网关按钮的单击槽 """
		NcgPcapDialog.connect(self.ModMediaBtn,QtCore.SIGNAL('clicked()'),self.on_ModMediaBtn_Clicked)

		""" 绑定删除媒体网关按钮的单击槽 """
		NcgPcapDialog.connect(self.DelMediaBtn,QtCore.SIGNAL('clicked()'),self.on_DelMediaBtn_Clicked)

		""" 绑定打包路径的浏览按钮的单击槽 """
		NcgPcapDialog.connect(self.AllCompressedPathScanBtn,QtCore.SIGNAL('clicked()'),self.on_AllCompressedPathScanBtn_Clicked)

		""" 绑定开始抓包按钮的单击槽 """
		NcgPcapDialog.connect(self.StartCapBtn,QtCore.SIGNAL('clicked()'),self.on_StartCapBtn_Clicked)

		""" 下面函数调用从全局变量中读取默认配置或者已存在配置，显示到界面 """
		self.loadConfToMainWindow()

	""" 日志模式：最新日志/全部日志 的radio按钮的单击事件槽 """
	@QtCore.pyqtSlot()
	def on_LogModRadioBtnGroup_Clicked(self):
		GLV.logMod = self.logModRadioBtnGroup.checkedId() #这里的RadioButton的ID和各模式的值已经设置为对应的，所以直接赋值即可

	@QtCore.pyqtSlot()
	def on_LogPathScanBtn_Clicked(self):
		""" 日志路径的“浏览”按钮的槽 """
		fileDialog = QtGui.QFileDialog()
		fileDialog.setFileMode(QtGui.QFileDialog.DirectoryOnly)
		fileDialog.setOption(QtGui.QFileDialog.ShowDirsOnly)
		logPath = fileDialog.getExistingDirectory(self.dialog,'选择日志文件夹','./')
		if logPath == "":
			return
		else:
			GLV.logPath = logPath
			self.LogPathEdit.setText(GLV.logPath)

	""" 抓取指定对端的复选框的单击槽 """
	@QtCore.pyqtSlot()
	def on_specificCapCheckBox_Clicked(self):
		GLV.oppositeCap = bool(self.specificCapCheckBox.isChecked())
		if GLV.oppositeCap == True:
			self.OthIpEdit.setEnabled(True)
			GLV.oppositeIp = ""
			self.OthIpEdit.clear()
		else:
			GLV.oppositeIp = ""
			self.OthIpEdit.clear()
			self.OthIpEdit.setEnabled(False)

	""" 对端IP编辑框的编辑槽 """
	@QtCore.pyqtSlot('QString')
	def on_OthIpEdit_textEdit(self,newText):
		GLV.oppositeIp = newText

	""" 添加扩展端口按钮的单击槽 """
	@QtCore.pyqtSlot()
	def on_AddPortablePortBtn_Clicked(self):
		self.PortablePortList.addItem('Please Edit Port')
		newItem = self.PortablePortList.item(self.PortablePortList.count()-1)
		GLV.cascPortablePort.append(str(newItem.text()))
		self.PortablePortList.openPersistentEditor(self.PortablePortList.item(self.PortablePortList.count()-1))
		#self.PortablePortList.item(self.PortablePortList.count()-1).setSelected(True)
		self.PortablePortList.setCurrentItem(newItem)

	""" 删除扩展端口按钮的单击槽 """
	@QtCore.pyqtSlot()
	def on_DelPortablePortBtn_Clicked(self):
		curRow = self.PortablePortList.currentRow()
		if curRow >= 0:
			if QtGui.QMessageBox.warning(None, QtCore.QString.fromUtf8('确认'), QtCore.QString.fromUtf8('确定要删除端口：'+ self.PortablePortList.currentItem().text() + '?'), QtGui.QMessageBox.Ok | QtGui.QMessageBox.Cancel) == QtGui.QMessageBox.Ok:
				removedItem = self.PortablePortList.takeItem(curRow)
				del GLV.cascPortablePort[curRow]

	""" 扩展端口列表的双击槽 """
	@QtCore.pyqtSlot('QListWidgetItem*')
	def on_PortablePortList_doubleClicked(self,item):
		self.PortablePortList.openPersistentEditor(item)

	""" 扩展端口列表的选中节点变化槽：用于关闭edit框 """
	@QtCore.pyqtSlot('QListWidgetItem*,QListWidgetItem*')
	def on_PortablePortList_curItemChange(self,current,previous):
		if previous != None:
			self.PortablePortList.closePersistentEditor(previous)

	""" 扩展端口列表的变化槽 """
	@QtCore.pyqtSlot('QListWidgetItem*')
	def on_PortablePortList_itemChanged(self,item):
		row = self.PortablePortList.row(item)
		if item.text() == "":
			self.PortablePortList.takeItem(row)
			del GLV.cascPortablePort[row]
		else:
			GLV.cascPortablePort[row] = str(item.text())

	""" 选择网络适配器按钮的单击槽 """
	@QtCore.pyqtSlot()
	def on_InterfaceChooseBtn_Clicked(self):
		errbuf = ctypes.create_string_buffer(NPCAP_ERROR_BUFF_SIZE)
		ifList = ctypes.POINTER(npcap_if_t)()
		if npcap_findalldevs(c_int(LOCAL_CAPTURE),None, c_int(0), None, None, ctypes.byref(ifList), errbuf) == NPCAP_ERROR:
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("获取网络设备接口错误：")+ errbuf.value)
			return
		IfChooseWin = IfChooseModule.IfChooseWindow()
		result, interfaceListTmp = IfChooseWin.show_window(ifList)
		if result == QtGui.QDialog.Rejected:
			return
		GLV.cascNetIfList = interfaceListTmp[:]
		self.cascInterfaceShowEdit.clear()
		for item in GLV.cascNetIfList:
			self.cascInterfaceShowEdit.append(item.ip)
		npcap_freealldevs(ifList)

	@QtCore.pyqtSlot()
	def on_AddMediaBtn_Clicked(self):
		""" 增加媒体网关按钮的单击槽 """
		AddMediaWin = AddMediaModule.AddMediaWindow()
		result, newMedia = AddMediaWin.show_add_window()
		if result == QtGui.QDialog.Rejected:
			return
		if newMedia.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
			if self.HAVE_LOCAL_MEDIA == True:
				QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("添加失败：\n 已经存在本地媒体网关"))
				return
		GLV.mediaList.append(newMedia)
		row = self.MediaTable.rowCount()
		self.MediaTable.insertRow(row)
		self.showMediaInfoOnMain(row,newMedia)

	@QtCore.pyqtSlot()
	def on_ModMediaBtn_Clicked(self):
		""" 修改媒体网关按钮的单击槽 """
		row = self.MediaTable.currentRow()
		if row < 0:
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("请先选择一行！"))
			return
		ModMediaWin = AddMediaModule.AddMediaWindow()
		result, newMedia = ModMediaWin.show_mod_window(row)
		if result == QtGui.QDialog.Rejected:
			return
		if newMedia.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
			for index, item in enumerate(GLV.mediaList):
				if item.mediaPosition == GLV.NPCAP_MEDIA_LOCAL and index != row:
					QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("修改失败：\n 已经存在本地媒体网关"))
					return
		GLV.mediaList[row] = newMedia
		self.showMediaInfoOnMain(row,newMedia)

	@QtCore.pyqtSlot()
	def on_DelMediaBtn_Clicked(self):
		""" 删除媒体网关按钮的单击槽 """
		row = self.MediaTable.currentRow()
		if row < 0:
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("请先选择一行！"))
			return
		del GLV.mediaList[row]
		self.MediaTable.removeRow(row)
		self.HAVE_LOCAL_MEDIA = False

	@QtCore.pyqtSlot()
	def on_StartCapBtn_Clicked(self):
		""" “开始抓包”按钮的槽 """
		import shutil
		""" 还是要先把这些配置保存到文件里面 """
		wd = os.getcwd() + '\\tmpDir'
		if os.path.exists(wd):
			shutil.rmtree(wd,True)
		os.mkdir(wd)
		if not os.path.exists(wd):
			QtGui.QMessageBox.information(None,QtCore.QString.fromUtf8("提示"),QtCore.QString.fromUtf8("创建工作目录失败！"))
			return
		GLV.workingDir = wd
		self.saveConfigToXml()

	@QtCore.pyqtSlot()
	def on_AllCompressedPathScanBtn_Clicked(self):
		""" 打包路径的“浏览”按钮的槽 """
		fileDialog = QtGui.QFileDialog()
		fileDialog.setConfirmOverwrite(True)
		fileDialog.setDefaultSuffix(QtCore.QString.fromUtf8(".zip"))
		fileDialog.setFilter(QtCore.QString.fromUtf8("*.zip"))
		fileDialog.setFileMode(QtGui.QFileDialog.AnyFile)
		#fileDialog.setFileMode(QtGui.QFileDialog.DirectoryOnly)
		logPath = fileDialog.getSaveFileName(self.dialog,'选择打包路径','./',QtCore.QString.fromUtf8('压缩文件(*.zip);;全部文件(*.*)'),QtCore.QString.fromUtf8('压缩文件(*.zip)'))
		if logPath == "":
			return
		else:
			GLV.logPath = logPath
			self.LogPathEdit.setText(GLV.logPath)

	def saveConfigToXml(self):
		""" 将页面配置保存到xml文件 """
		root = ET.Element('NpcapConfigure')
		logConfEle = ET.SubElement(root,'LogPathConfigure')
		logModeEle = ET.SubElement(logConfEle,'LogMode')
		logModeEle.text = str(GLV.logMod)
		logPathEle = ET.SubElement(logConfEle,'LogPath')
		logPathEle.text = GLV.logPath
		PacCapConfEle = ET.SubElement(root,'PacketCaptureConfigure')
		OppositeCapEle = ET.SubElement(PacCapConfEle,'OppositeCap')
		if GLV.oppositeCap == False:
			OppositeCapEle.text = '0'
		else:
			OppositeCapEle.text = '1'
			OppositeIpEle = ET.SubElement(PacCapConfEle,'OppositeIp')
			OppositeIpEle.text = GLV.oppositeIp
		CascConfEle = ET.SubElement(PacCapConfEle,'CascadeConfigure')
		DevListEle = ET.SubElement(CascConfEle,'DeviceList')
		for devItem in GLV.cascNetIfList:
			itemEle = ET.SubElement(DevListEle,'Item',{'ip':devItem.ip})
			itemEle.text = devItem.name
		SipPortEle = ET.SubElement(CascConfEle,'SipPort')
		SipPortEle.text = GLV.cascSipPort
		ClientPortEle = ET.SubElement(CascConfEle,'ClientPort')
		ClientPortEle.text = GLV.cascClientPort
		PortablePortEle = ET.SubElement(CascConfEle,'PortablePortList')
		for portItem in GLV.cascPortablePort:
			itemEle = ET.SubElement(PortablePortEle,'Item')
			itemEle.text = portItem
		MediaConfEle = ET.SubElement(PacCapConfEle,'MediaConfigure')
		""" 先遍历，把本地media添加到最前面 """
		for media in GLV.mediaList:
			if media.mediaPosition == GLV.NPCAP_MEDIA_LOCAL:
				MediaEle = ET.SubElement(MediaConfEle,'LocalMedia')
				for devItem in media.netIfList:
					itemEle = ET.SubElement(MediaEle,'Item',{'ip':devItem.ip})
					itemEle.text = devItem.name
				RtspPortEle = ET.SubElement(MediaEle,'RtspPort')
				RtspPortEle.text = media.rtspPort
				UdpPortBaseEle = ET.SubElement(MediaEle,'UdpPortBase')
				UdpPortBaseEle.text = media.udpPortBase
				UdpPortNumEle = ET.SubElement(MediaEle,'UdpPortNum')
				UdpPortNumEle.text = media.udpPortNum
				RtspSendPortBaseEle = ET.SubElement(MediaEle,'RtspSendPortBase')
				RtspSendPortBaseEle.text = media.rtspSendPortBase
				RtspSendPortNumEle = ET.SubElement(MediaEle,'RtspSendPortNum')
				RtspSendPortNumEle.text = media.rtspSendPortNum
				RtspRecvPortBaseEle = ET.SubElement(MediaEle,'RtspRecvPortBase')
				RtspRecvPortBaseEle.text = media.rtspRecvPortBase
				RtspRecvPortNumEle = ET.SubElement(MediaEle,'RtspRecvPortNum')
				RtspRecvPortNumEle.text = media.rtspRecvPortNum
		""" 然后遍历写远程media """
		for media in GLV.mediaList:
			if media.mediaPosition != GLV.NPCAP_MEDIA_LOCAL:
				MediaEle = ET.SubElement(MediaConfEle,'RemoteMedia')
				ConnIpEle = ET.SubElement(MediaEle,'ConnectIp')
				ConnIpEle.text = media.remoteInfo.ip
				ConnPortEle = ET.SubElement(MediaEle,'ConnectPort')
				ConnPortEle.text = media.remoteInfo.port
				AuthEle = ET.SubElement(MediaEle,'Authentication',{'use':media.remoteInfo.authMode})
				UserNameEle = ET.SubElement(AuthEle,'UserName')
				UserNameEle.text = media.remoteInfo.usrName
				PwdEle = ET.SubElement(AuthEle,'PassWord')
				PwdEle.text = media.remoteInfo.pwd
				for devItem in media.netIfList:
					itemEle = ET.SubElement(MediaEle,'Item',{'ip':devItem.ip})
					itemEle.text = devItem.name
				RtspPortEle = ET.SubElement(MediaEle,'RtspPort')
				RtspPortEle.text = media.rtspPort
				UdpPortBaseEle = ET.SubElement(MediaEle,'UdpPortBase')
				UdpPortBaseEle.text = media.udpPortBase
				UdpPortNumEle = ET.SubElement(MediaEle,'UdpPortNum')
				UdpPortNumEle.text = media.udpPortNum
				RtspSendPortBaseEle = ET.SubElement(MediaEle,'RtspSendPortBase')
				RtspSendPortBaseEle.text = media.rtspSendPortBase
				RtspSendPortNumEle = ET.SubElement(MediaEle,'RtspSendPortNum')
				RtspSendPortNumEle.text = media.rtspSendPortNum
				RtspRecvPortBaseEle = ET.SubElement(MediaEle,'RtspRecvPortBase')
				RtspRecvPortBaseEle.text = media.rtspRecvPortBase
				RtspRecvPortNumEle = ET.SubElement(MediaEle,'RtspRecvPortNum')
				RtspRecvPortNumEle.text = media.rtspRecvPortNum
		WorkingDirEle = ET.SubElement(PacCapConfEle,'WorkingDirectory')
		WorkingDirEle.text = GLV.workingDir
		CompressPathEle = ET.SubElement(root,'CompressPath')
		CompressPathEle.text = GLV.compressPath
		ET.ElementTree(root).write('.\\npcap.conf.xml')
		print ET.tostring(root)


	def showMediaInfoOnMain(self,row,mediaItem):
		""" 在主页面的media表格中显示media信息的过程写做一个函数 """
		if mediaItem.mediaPosition == GLV.NPCAP_MEDIA_REMOTE:
			tableItem = QtGui.QTableWidgetItem(mediaItem.remoteInfo.ip)
		else:
			tableItem = QtGui.QTableWidgetItem("Local")
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,0,tableItem)
		tableItem = QtGui.QTableWidgetItem(str(len(mediaItem.netIfList)))
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,1,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.rtspPort)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,2,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.udpPortBase)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,3,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.udpPortNum)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,4,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.rtspRecvPortBase)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,5,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.rtspRecvPortNum)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,6,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.rtspSendPortBase)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,7,tableItem)
		tableItem = QtGui.QTableWidgetItem(mediaItem.rtspSendPortNum)
		tableItem.setTextAlignment(QtCore.Qt.AlignCenter)
		self.MediaTable.setItem(row,8,tableItem)

	""" 从全局变量中读取配置，显示到界面，程序开始时调用的函数 """
	def loadConfToMainWindow(self):
		if GLV.logMod == GLV.NPCAP_LOG_NEWEST:
			self.NewestLogRadioBtn.setChecked(True)
			self.AllLogRadioBtn.setChecked(False)
		else:
			self.NewestLogRadioBtn.setChecked(False)
			self.AllLogRadioBtn.setChecked(True)
		self.LogPathEdit.setText(GLV.logPath)
		self.SipPortEdit.setText(GLV.cascSipPort)
		self.PrivatePortEdit.setText(GLV.cascClientPort)
		self.AllCompressedPathEdit.setText(GLV.compressPath)
		self.specificCapCheckBox.setChecked(GLV.oppositeCap)
		if GLV.oppositeCap == True:
			self.OthIpEdit.setText(GLV.oppositeIp)
		else:
			self.OthIpEdit.setEnabled(False)
		for portablePort in GLV.cascPortablePort:
			self.PortablePortList.addItem(portablePort)

		for deviceItem in GLV.cascNetIfList:
			self.cascInterfaceShowEdit.append(deviceItem.ip)

		for mediaItem in GLV.mediaList:
			row = self.MediaTable.rowCount()
			self.MediaTable.insertRow(row)
			self.showMediaInfoOnMain(row,mediaItem)

""" 通过进程信息读取cascade和media的目录 """
def searchProcessPath():
	""" 通过wmic process命令获取进程可执行文件路径 """
	cascPathPip = os.popen('wmic process where name="cascade.exe" get executablepath')
	mediaPathPip = os.popen('wmic process where name="media.exe" get executablepath')
	cascPath = cascPathPip.read()
	mediaPath = mediaPathPip.read()
	""" 路径中包含可执行文件名称，要去掉，并且处理异常情况 """
	splitIndex = cascPath.find("\n")
	if splitIndex <=5:
		cascPath = ""
	else:
		cascPath = cascPath[splitIndex+1:]
		splitIndex = cascPath.find("cascade.exe")
		if splitIndex != -1:
			cascPath = cascPath[:splitIndex]
		else:
			if os.path.isdir(cascPath) != True:
				cascPath = ""
	splitIndex = mediaPath.find("\n")
	if splitIndex <= 5:
		mediaPath = ""
	else:
		mediaPath = mediaPath[splitIndex+1:]
		splitIndex = mediaPath.find("media.exe")
		if splitIndex != -1:
			mediaPath = mediaPath[:splitIndex]
		else:
			if os.path.isdir(mediaPath) != True:
				mediaPath = ""
	return {'cascPath':cascPath,'mediaPath':mediaPath}

""" 
从cascade.xml配置文件中读取SIP端口和客户端端口信息
\param cascadexmlPath [IN] cascade.xml配置文件的绝对路径
 """
def getPortFromCascaceXml(cascadexmlPath):
	try:
		tree = ET.parse(cascadexmlPath)
	except Exception,e:
		QMessageBox.information(None,"提示","读取cascade.xml出现错误："+e.str())
		return
	root = tree.getroot()
	protocolEle = root.find('Protocol')
	HkpProtoEle = protocolEle.find('Hkp')
	ClientPort = HkpProtoEle.find('ClientPort').text
	if ClientPort == "":
		GLV.cascClientPort = 'XML中未找到'
	else:
		GLV.cascClientPort = ClientPort
	DB33ProtoEle = protocolEle.find('DB33')
	SipPort = DB33ProtoEle.find('SIPPort').text
	if SipPort == "":
		GLV.cascSipPort = 'XML中未找到'
	else:
		GLV.cascSipPort = SipPort
	return

""" 获取网络设备接口函数，默认全选 """
def initCascCaptureInterface():
	errbuf = ctypes.create_string_buffer(NPCAP_ERROR_BUFF_SIZE)
	ifList = ctypes.POINTER(npcap_if_t)()
	if npcap_findalldevs(c_int(LOCAL_CAPTURE),None, c_int(0), None, None, ctypes.byref(ifList), errbuf) == NPCAP_ERROR:
		QtGui.QMessageBox.information(None,"提示","获取网络设备接口错误："+ errbuf.value)
		return	
	cap_if = ifList
	while bool(cap_if) == True:
		interface = GLV.DeviceItem()
		interface.name = cap_if.contents.name
		interface.ip = cap_if.contents.ip
		cap_if = cap_if.contents.next
		GLV.cascNetIfList.append(interface)
	npcap_freealldevs(ifList)

""" 获取media端口信息 """
def getPortFromMediaXml(mediaxmlPath,media):
	try:
		tree = ET.parse(mediaxmlPath)
	except Exception,e:
		QMessageBox.information(None,"提示","读取media.xml出现错误："+e.str())
		return
	root = tree.getroot()

	rtspPort = root.find('RtspPort').text
	if rtspPort == "":
		media.rtspPort = 'XML中未找到'
	else:
		media.rtspPort = rtspPort

	udpPortBase = root.find('UdpPortBase').text
	if udpPortBase == "":
		media.udpPortBase = 'XML中未找到'
	else:
		media.udpPortBase = udpPortBase

	udpPortNum = root.find('UdpPortNum').text
	if udpPortNum == "":
		media.udpPortNum = 'XML中未找到'
	else:
		media.udpPortNum = udpPortNum

	rtspSendPortBase = root.find('RtspAgentPortBase').text
	if rtspSendPortBase == "":
		media.rtspSendPortBase = 'XML中未找到'
	else:
		media.rtspSendPortBase = rtspSendPortBase

	rtspSendPortNum = root.find('RtspAgentPortNum').text
	if rtspSendPortNum == "":
		media.rtspSendPortNum = 'XML中未找到'
	else:
		media.rtspSendPortNum = rtspSendPortNum

	rtspRecvPortBase = root.find('MediaClientPortBase').text
	if rtspRecvPortBase == "":
		media.rtspRecvPortBase = 'XML中未找到'
	else:
		media.rtspRecvPortBase = rtspRecvPortBase

	rtspRecvPortNum = root.find('MediaClientPortNum').text
	if rtspRecvPortNum == "":
		media.rtspRecvPortNum = 'XML中未找到'
	else:
		media.rtspRecvPortNum = rtspRecvPortNum
	return

""" 初始化全局的localMedia信息 """
def initLocalMedia(mediaxmlPath):
	localMedia = GLV.Media()
	""" 先获取网络设备接口，默认全选 """
	errbuf = ctypes.create_string_buffer(NPCAP_ERROR_BUFF_SIZE)
	ifList = ctypes.POINTER(npcap_if_t)()
	if npcap_findalldevs(c_int(LOCAL_CAPTURE),None, c_int(0), None, None, ctypes.byref(ifList), errbuf) == NPCAP_ERROR:
		QtGui.QMessageBox.information(None,"提示","初始化本地媒体网关时获取网络设备接口错误："+ errbuf.value)
		return	
	cap_if = ifList
	while bool(cap_if) == True:
		interface = GLV.DeviceItem()
		interface.name = cap_if.contents.name
		interface.ip = cap_if.contents.ip
		cap_if = cap_if.contents.next
		localMedia.netIfList.append(interface)
	npcap_freealldevs(ifList)
	""" 然后获取media相关的端口 """
	getPortFromMediaXml(mediaxmlPath,localMedia)
	GLV.mediaList.append(localMedia)
	NcgPcapMainWindow.HAVE_LOCAL_MEDIA = True

""" 根据cascade和media的可执行文件路径获取配置文件中的信息 """
def getConfigFromExePath(processesPath):
	if processesPath['cascPath'] != "":
		""" 如果运行了cascade，能确定log路径并从cascade.xml中读取端口信息 """
		GLV.logPath = processesPath['cascPath'] + "log\\"
		getPortFromCascaceXml(processesPath['cascPath'] + "cascade.xml")
		""" 获取网络设备接口，默认全选 """
		initCascCaptureInterface()
	else:
		""" 如果没运行cascade，显示出来 """
		GLV.cascSipPort = '未找到Cascade'
		GLV.cascClientPort = '未找到Cascade'
	if processesPath['mediaPath'] != "":
		""" 创建全局的本地media类，并获取端口和适配器信息 """
		initLocalMedia(processesPath['mediaPath']+"media.xml")
	else:
		""" 如果没找到media的可执行文件路径，即没有本地media运行，则不做操作 """
	return

if __name__ == "__main__":
	import sys

	""" 启动程序看是否有存在的配置文件，先读取 """
	if os.path.exists("./Npcap.cof.xml") == True:
		""" 读取配置文件 """
		pass
	else:
		try:
			""" 首先获取cascade和media的路径 """
			processesPath = searchProcessPath()
			""" 然后通过可执行文件路径获取xml配置文件信息 """
			getConfigFromExePath(processesPath)
		except Exception, e:
			""" 跳出一个窗口吧，提示有错误 """
			QtGui.QMessageBox.information(None,"提示","读取cascade.xml出现错误："+e.str())
		GLV.compressPath = os.getcwd() + "\\" + "NcgPcap_" + time.strftime('%Y%m%d%H%M%S',time.localtime())+".zip"
		GLV.oppositeCap = False #默认不抓取指定对端的包，而是全抓
		GLV.oppositeIp = "" #默认使用空对端IP地址
		GLV.logMod = GLV.NPCAP_LOG_NEWEST #默认打包最新日志
		GLV.cascPortablePort = [] #默认没有扩展端口


		

	app = QtGui.QApplication(sys.argv)
	"""NcgPcapWindow = QtGui.QDialog()
	ui = NcgPcapMainWindow()
	ui.setupUi(NcgPcapWindow)
	NcgPcapWindow.show()"""
	NcgPcapWindow = NcgPcapMainWindow()
	NcgPcapWindow.show_window()
	sys.exit(app.exec_())
# -*- coding: utf-8 -*-

""" 压缩日志的范围 """
NPCAP_LOG_NEWEST = 0 #只打包最新日志
NPCAP_LOG_ALL = 1 # 打包全部日志

""" 远程主机的鉴权模式 """
NPCAP_RMT_AUTH_NULL = 0 #无鉴权
NPCAP_RMT_AUTH_PWD = 1 #密码鉴权

""" 媒体网关位置 """
NPCAP_MEDIA_LOCAL = 0 #媒体网关在本地
NPCAP_MEDIA_REMOTE = 1 #媒体网关在远程主机

""" 网络设备表示 """
class DeviceItem:
	name = "" #设备名称
	ip="" #设备IP
	netmask = "" #設備子網掩碼

	def __init__(self, devName="", devIp="",devNetmask=""):
		self.name = devName
		self.ip = devIp
		self.netmask = devNetmask


""" 远程抓包时的远程主机表示 """
class RemotePc:
	ip = "" #远程主机IP
	port = '2002' #远程抓包的TCP连接端口
	authMode = NPCAP_RMT_AUTH_PWD #远程主机的鉴权模式：0，无鉴权；1，密码鉴权
	usrName = "" #远程主机用户名
	pwd = "" #远程主机密码

	def __init__(self, rmtIp="", rmtPort='2002', rmtAuthMode=0, rmtUsrName="", rmtPwd=""):
		self.ip = rmtIp
		self.port = rmtPort
		self.authMode = rmtAuthMode
		self.usrName = rmtUsrName
		self.pwd = rmtPwd

class Media:
	mediaPosition = NPCAP_MEDIA_LOCAL #媒体网关位置
	netIfList = [] #抓包的网络设备列表
	rtspPort = '7087' #媒体网关RTSP端口
	udpPortBase = '5100' #媒体网关UDP流传输开始端口
	udpPortNum = '300' #媒体网关UDP流传输端口数目
	rtspSendPortBase = '25000' #媒体网关RTSP发送流开始端口
	rtspSendPortNum = '300' #媒体网关RTSP发送流端口数目
	rtspRecvPortBase = '26000' #媒体网关RTSP接收流开始端口
	rtspRecvPortNum = '300' #媒体网关RTSP接收流端口数目

	def __init__(self, mediaPositionPara = NPCAP_MEDIA_LOCAL, netIfListPara = [], rtspPortPara = '7087', udpPortBasePara = '5100', udpPortNumPara = '300', rtspSendPortBasePara = '25000', rtspSendPortNumPara = '300', rtspRecvPortBasePara = '26000', rtspRecvPortNumPara = '300'):
		self.mediaPosition = mediaPositionPara
		self.netIfList = netIfListPara[:]
		self.udpPortBase = udpPortBasePara
		self.udpPortNum = udpPortNumPara
		self.rtspPort = rtspPortPara
		self.rtspSendPortBase = rtspSendPortBasePara
		self.rtspSendPortNum = rtspSendPortNumPara
		self.rtspRecvPortBase = rtspRecvPortBasePara
		self.rtspRecvPortNum = rtspRecvPortNumPara

	def setRemote(self, rmtInfo = RemotePc()):
		self.mediaPosition = NPCAP_MEDIA_REMOTE
		self.remoteInfo = rmtInfo

logMod = NPCAP_LOG_NEWEST

logPath = "" #日志文件路径

oppositeCap = False #是否抓取指定对端的包

oppositeIp = "" #对端信令网关IP地址

cascSipPort = '7100' #信令网关SIP端口

cascClientPort = '7099' #信令网关监听客户端请求端口

cascPortablePort = [] #信令网关机器上的抓包扩展端口

cascNetIfList = [] #信令网关抓包网络设备列表

mediaList = [] #媒体网关列表

workingDir = "" #抓包结果保存的路径（不需要具体文件名）

compressPath = "" #最终结果打包路径



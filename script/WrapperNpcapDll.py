# -*- coding: utf-8 -*-

from ctypes import *
import sys

WIN32=False
HAVE_REMOTE=False

NPCAP_ERROR_BUFF_SIZE = 256 #错误buffer大小

""" 标识接口调用成功与否，若错误，可在函数调用的errbuf中得到错误信息 """
NPCAP_SUCC = 0 #调用接口正确
NPCAP_ERROR = -1 #调用接口错误

""" npcap_findalldevs接口的第一个参数的取值，标识抓包位置：本地or远程 """
LOCAL_CAPTURE = 0 #本地抓包
REMOTE_CAPTURE = 1 #远程抓包


if sys.platform.startswith('win'):
	WIN32=True
	HAVE_REMOTE=True

if WIN32:
	SOCKET = c_uint
	_lib=CDLL('npcap.dll')
else:
	SOCKET = c_int
	_lib=CDLL(find_library('pcap')) #这个再定，没写呢

class npcap_if_t(Structure):
	pass
npcap_if_t._fields_ = [('next',POINTER(npcap_if_t)),
						('name',c_char_p),
						('description',c_char_p),
						('ip',c_char_p),
						('netmask',c_char_p)]

def npcap_if_iterator(cap_iterfaces):
	cap_if = cap_iterfaces
	while bool(cap_if) == True:
		yield cap_if.contents
		cap_if = cap_if.contents.next

npcap_findalldevs = _lib.npcap_findalldevs
npcap_findalldevs.restype = c_int
npcap_findalldevs.argtypes = [c_int, c_char_p, c_int, c_char_p, c_char_p, POINTER(POINTER(npcap_if_t)),c_char_p]

npcap_freealldevs = _lib.npcap_freealldevs
npcap_freealldevs.restype = c_int
npcap_freealldevs.argtypes = [POINTER(npcap_if_t)]

npcap_pcap_start = _lib.npcap_pcap_start
npcap_pcap_start.restype = c_int
npcap_pcap_start.argtypes = [c_char_p]

npcap_pcap_stop = _lib.npcap_pcap_stop
npcap_pcap_stop.restype = c_int


#ifndef _NPCAP_CONFIG_H_
#define _NPCAP_CONFIG_H_

#include <string>
#include <list>
using namespace std;

namespace CONFIG{

	/*!
	 * \brief 媒体网关位置枚举类型
	 */
	enum MEDIA_POSITION
	{
		NPCAP_MEDIA_LOCAL = 0,	///< 媒体网关在本地
		NPCAP_MEDIA_REMOTE		///< 媒体网关在远程主机
	};

	/*!
	 * \brief 远程主机鉴权模式
	 */
	enum REMOTE_AUTH_MODE
	{
		NPCAP_RMT_AUTH_NULL = 0,	///< 无鉴权
		NPCAP_RMT_AUTH_PWD			///< 密码鉴权
	};

	/*!
	 * \brief 内部使用的抓包接口的类
	 *
	 * 在读取npcap.conf.xml配置文件中，将读取到的需要抓包的网络设备接口的信息保存在该类中。
	 * 在实际抓包时，使用到该处的name进行打开网络设备操作。
	 * 并在遭遇错误以及抓包结果文件命名时包含接口的IP来标识是哪个网卡。
	 */
	struct npcap_if_internal
	{
	//public:
		string if_name;						///< 网络设备接口名称（带rpcap://前缀）
		string if_ip;						///< 网络设备接口IP地址
		npcap_if_internal()
		{
			if_name = "";
			if_ip = "";
		}
		/*~npcap_if_internal()
		{

		}*/
	};

	/*!
	 * \brief 内部使用的标识媒体网关的类
	 *
	 * 该类中包含媒体网关要抓包的端口范围和网络设备接口
	 * 对于远程媒体网关，还包含远程主机的IP、端口、用户名和密码
	 */
	struct npcap_media
	{
	//public:
		MEDIA_POSITION iMediaPosition;
		REMOTE_AUTH_MODE iRemoteAuthMode;
		string strRmtIp;
		int	iRmtPort;
		string strRmtAuthUsrName;
		string strRmtAuthPwd;
		list<npcap_if_internal> listInterfaces;
		int iRtspPort;
		int iUdpPortBase;
		int iUdpPortNum;
		int iRtspSendPortBase;
		int iRtspSendPortNum;
		int iRtspRecvPortBase;
		int iRtspRecvPortNum;
		npcap_media()
		{
			iMediaPosition = NPCAP_MEDIA_LOCAL;
			iRemoteAuthMode = NPCAP_RMT_AUTH_PWD;
			strRmtAuthUsrName = "";
			strRmtAuthPwd = "";
			strRmtIp = "";
			iRmtPort = 0;
			listInterfaces.clear();
			iRtspPort = 0;
			iUdpPortBase = 0;
			iUdpPortNum = 0;
			iRtspSendPortBase = 0;
			iRtspSendPortNum = 0;
			iRtspRecvPortBase = 0;
			iRtspRecvPortNum = 0;
		}
	};

	bool g_bOppositeCap = false;			///< 是否指定对端抓取
	char g_szOppositeIp[16] = {0};			///< 对端抓取IP
	list<npcap_if_internal> g_cascIfList;	///< 信令网关网络设备接口列表
	int g_iSipPort = 0;						///< 信令网关SIP端口
	int g_iClientPort = 0;					///< 信令网关客户端端口
	list<int> g_cascExtendPortList;			///< 信令网关抓包扩展端口
	list<npcap_media> g_mediaList;			///< 媒体网关列表
	string g_strWorkingDirectory;				///< 工作目录，最后打包工作目录里面的内容
}

#endif

/*!
 * \file npcap_internal_def.h
 *
 * \brief 內部變量等定義頭文件。
 *
 * 該文件包含了所有的內部使用的變量、類型和宏的定義。
 * 該文件被npcap_internal.h包含，構成內層抽象模塊。
 */

#ifndef _NPCAP_INTERNAL_DEF_H_
#define _NPCAP_INTERNAL_DEF_H_

#include <string>
#include <list>

/*! 
 * \brief 网络设备接口结构体
 *
 * 该结构体用于向外部传递网络设备接口信息，以供进行抓包的接口选择。
 */
struct npcap_if
{
	struct npcap_if		*next;					///< 下一个接口的指针
	char				*name;					///< 接口名称
	char				*description;			///< 接口描述
	char				*ip;					///< IP地址
	char				*netmask;				///< 子网掩码
};

struct npcap_rmt_info
{
	char				rmt_ip[16];
	int					rmt_port;
	int					rmt_auth_mode;	//0--None or 1-PWD
	char				rmt_auth_usrname[64];
	char				rmt_auth_pwd[64];
};

/*!
 * \brief 抓包單元位置---本地還是遠程
 */
enum CAPUNIT_POSITION
{
	NPCAP_CAPUNIT_LOCAL = 0,			///< 抓包單元在本地主機
	NPCAP_CAPUNIT_REMOTE				///< 抓包單元在遠程主機
};

/*!
 * \brief 处理每个包的回调函数
 *
 * 程序中在获取到每个包的时候都调用该回调函数进行包数据的处理，每个抓包单元有自己的回调函数实例。
 * 
 * \param user [IN] 用户数据，外部设置的传入参数
 * \param pDumper [OUT] dump成抓包文件的句柄，由回調函數中自行調用pcap_dump函數進行保存，主要考慮可能外層繼續進行一層過濾
 * \param pkt_header [OUT] 抓包中生成的头部数据，与pcap库的相同，不包含实际网络抓包中的数据
 * \param pkt_data [OUT] 网络抓包的实际数据，一包的所有内容。
 */
typedef void (*npcap_handler)( void							*user
							  , void						*pDumper
							  , const struct pcap_pkthdr	*pkt_header
							  , const u_char				*pkt_data);


/*!
 * \brief 媒体网关位置枚举类型
 */
enum MEDIA_POSITION
{
	NPCAP_MEDIA_LOCAL = 0,		///< 媒体网关在本地
	NPCAP_MEDIA_REMOTE			///< 媒体网关在远程主机
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
	std::string			if_name;				///< 网络设备接口名称（带rpcap://前缀）
	std::string			if_ip;					///< 网络设备接口IP地址
	std::string			if_netmask;				///< 網絡設備接口子網掩碼
	npcap_if_internal()
	{
		if_name = "";
		if_ip	= "";
		if_netmask = "";
	}
};

/*!
 * \brief 内部使用的标识媒体网关的类
 *
 * 该类中包含媒体网关要抓包的端口范围和网络设备接口
 * 对于远程媒体网关，还包含远程主机的IP、端口、用户名和密码
 */
struct npcap_media
{
	MEDIA_POSITION					iMediaPosition;
	REMOTE_AUTH_MODE				iRemoteAuthMode;
	std::string						strRmtIp;
	int								iRmtPort;
	std::string						strRmtAuthUsrName;
	std::string						strRmtAuthPwd;
	std::list<npcap_if_internal>	listInterfaces;
	int								iRtspPort;
	int								iUdpPortBase;
	int								iUdpPortNum;
	int								iRtspSendPortBase;
	int								iRtspSendPortNum;
	int								iRtspRecvPortBase;
	int								iRtspRecvPortNum;
	npcap_media()
	{
		iMediaPosition			= NPCAP_MEDIA_LOCAL;
		iRemoteAuthMode			= NPCAP_RMT_AUTH_PWD;
		strRmtAuthUsrName		= "";
		strRmtAuthPwd			= "";
		strRmtIp				= "";
		iRmtPort				= 0;
		listInterfaces.clear();
		iRtspPort				= 0;
		iUdpPortBase			= 0;
		iUdpPortNum				= 0;
		iRtspSendPortBase		= 0;
		iRtspSendPortNum		= 0;
		iRtspRecvPortBase		= 0;
		iRtspRecvPortNum		= 0;
	}
};


#endif

/*!
 * \file npcap_internal_def.h
 *
 * \brief �Ȳ�׃���ȶ��x�^�ļ���
 *
 * ԓ�ļ����������еăȲ�ʹ�õ�׃������ͺͺ�Ķ��x��
 * ԓ�ļ���npcap_internal.h���������ɃȌӳ���ģ�K��
 */

#ifndef _NPCAP_INTERNAL_DEF_H_
#define _NPCAP_INTERNAL_DEF_H_

#include <string>
#include <list>

/*! 
 * \brief �����豸�ӿڽṹ��
 *
 * �ýṹ���������ⲿ���������豸�ӿ���Ϣ���Թ�����ץ���Ľӿ�ѡ��
 */
struct npcap_if
{
	struct npcap_if		*next;					///< ��һ���ӿڵ�ָ��
	char				*name;					///< �ӿ�����
	char				*description;			///< �ӿ�����
	char				*ip;					///< IP��ַ
	char				*netmask;				///< ��������
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
 * \brief ץ����Ԫλ��---����߀���h��
 */
enum CAPUNIT_POSITION
{
	NPCAP_CAPUNIT_LOCAL = 0,			///< ץ����Ԫ�ڱ������C
	NPCAP_CAPUNIT_REMOTE				///< ץ����Ԫ���h�����C
};

/*!
 * \brief ����ÿ�����Ļص�����
 *
 * �������ڻ�ȡ��ÿ������ʱ�򶼵��øûص��������а����ݵĴ���ÿ��ץ����Ԫ���Լ��Ļص�����ʵ����
 * 
 * \param user [IN] �û����ݣ��ⲿ���õĴ������
 * \param pDumper [OUT] dump��ץ���ļ��ľ�����ɻ��{�����������{��pcap_dump�����M�б��棬��Ҫ���]��������^�m�M��һ���^�V
 * \param pkt_header [OUT] ץ�������ɵ�ͷ�����ݣ���pcap�����ͬ��������ʵ������ץ���е�����
 * \param pkt_data [OUT] ����ץ����ʵ�����ݣ�һ�����������ݡ�
 */
typedef void (*npcap_handler)( void							*user
							  , void						*pDumper
							  , const struct pcap_pkthdr	*pkt_header
							  , const u_char				*pkt_data);


/*!
 * \brief ý������λ��ö������
 */
enum MEDIA_POSITION
{
	NPCAP_MEDIA_LOCAL = 0,		///< ý�������ڱ���
	NPCAP_MEDIA_REMOTE			///< ý��������Զ������
};

/*!
 * \brief Զ��������Ȩģʽ
 */
enum REMOTE_AUTH_MODE
{
	NPCAP_RMT_AUTH_NULL = 0,	///< �޼�Ȩ
	NPCAP_RMT_AUTH_PWD			///< �����Ȩ
};

/*!
 * \brief �ڲ�ʹ�õ�ץ���ӿڵ���
 *
 * �ڶ�ȡnpcap.conf.xml�����ļ��У�����ȡ������Ҫץ���������豸�ӿڵ���Ϣ�����ڸ����С�
 * ��ʵ��ץ��ʱ��ʹ�õ��ô���name���д������豸������
 * �������������Լ�ץ������ļ�����ʱ�����ӿڵ�IP����ʶ���ĸ�������
 */
struct npcap_if_internal
{
	std::string			if_name;				///< �����豸�ӿ����ƣ���rpcap://ǰ׺��
	std::string			if_ip;					///< �����豸�ӿ�IP��ַ
	std::string			if_netmask;				///< �W�j�O��ӿ��ӾW�ڴa
	npcap_if_internal()
	{
		if_name = "";
		if_ip	= "";
		if_netmask = "";
	}
};

/*!
 * \brief �ڲ�ʹ�õı�ʶý�����ص���
 *
 * �����а���ý������Ҫץ���Ķ˿ڷ�Χ�������豸�ӿ�
 * ����Զ��ý�����أ�������Զ��������IP���˿ڡ��û���������
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
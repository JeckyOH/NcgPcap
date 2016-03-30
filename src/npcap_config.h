#ifndef _NPCAP_CONFIG_H_
#define _NPCAP_CONFIG_H_

#include <string>
#include <list>
using namespace std;

namespace CONFIG{

	/*!
	 * \brief ý������λ��ö������
	 */
	enum MEDIA_POSITION
	{
		NPCAP_MEDIA_LOCAL = 0,	///< ý�������ڱ���
		NPCAP_MEDIA_REMOTE		///< ý��������Զ������
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
	//public:
		string if_name;						///< �����豸�ӿ����ƣ���rpcap://ǰ׺��
		string if_ip;						///< �����豸�ӿ�IP��ַ
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
	 * \brief �ڲ�ʹ�õı�ʶý�����ص���
	 *
	 * �����а���ý������Ҫץ���Ķ˿ڷ�Χ�������豸�ӿ�
	 * ����Զ��ý�����أ�������Զ��������IP���˿ڡ��û���������
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

	bool g_bOppositeCap = false;			///< �Ƿ�ָ���Զ�ץȡ
	char g_szOppositeIp[16] = {0};			///< �Զ�ץȡIP
	list<npcap_if_internal> g_cascIfList;	///< �������������豸�ӿ��б�
	int g_iSipPort = 0;						///< ��������SIP�˿�
	int g_iClientPort = 0;					///< �������ؿͻ��˶˿�
	list<int> g_cascExtendPortList;			///< ��������ץ����չ�˿�
	list<npcap_media> g_mediaList;			///< ý�������б�
	string g_strWorkingDirectory;				///< ����Ŀ¼�����������Ŀ¼���������
}

#endif
// NcgPcap.cpp : ���� DLL Ӧ�ó���ĵ���������
//

//#include "stdafx.h"
#include "npcap_internal.h"

#include <vector>
using namespace std;


NCGPCAP_API int npcap_findalldevs(int iIsLocal,char* strRmtIp, int iRmtPort, char* strRmtUsrName, char* strRmtPwd, npcap_if_t **interfaces, char* errbuf)
{
	/*! ����/Զ��ץ��ָʾ��������ȷʱֱ�ӷ��� */
	if (iIsLocal != LOCAL_CAPTURE && iIsLocal != REMOTE_CAPTURE)
	{
		if (errbuf != NULL)
		{
			memset(errbuf,0,NPCAP_ERROR_BUFF_SIZE);
			_snprintf(errbuf,NPCAP_ERROR_BUFF_SIZE-1,"The indicator of local/remote mode to capture packets is wrong, should be 0 or 1, now:[%d]",iIsLocal);
		}
		return NPCAP_ERROR;
	}

	pcap_rmtauth* rmt_auth = NULL;
	char strSource[PCAP_BUF_SIZE] = {0};
	_snprintf(strSource,PCAP_BUF_SIZE-1,"%s",PCAP_SRC_IF_STRING);

	/*! Զ��ץ����װ��Ȩ��Ϣ */
	if (iIsLocal == REMOTE_CAPTURE)
	{
		/*! ��������ȷʱֱ�ӷ��� */
		if (strRmtIp == NULL || iRmtPort <=0)
		{
			if (errbuf != NULL)
			{
				memset(errbuf,0,NPCAP_ERROR_BUFF_SIZE);
				_snprintf(errbuf,NPCAP_ERROR_BUFF_SIZE-1,"Parameters are incorrect, remote IP or port is invalid.IP,port:[%d]",iRmtPort);
			}
			return NPCAP_ERROR;
		}
		_snprintf(strSource,PCAP_BUF_SIZE-1,"%s%s:%d/",PCAP_SRC_IF_STRING,strRmtIp,iRmtPort);
		rmt_auth = new pcap_rmtauth;
		memset(rmt_auth,0,sizeof(pcap_rmtauth));
		if (strRmtUsrName == NULL && strRmtPwd ==NULL)
		{
			/*! 
			 * rmt_auth.type = RPCAP_RMTAUTH_NULL;
			 * ���Բ�д�ˣ�����pcap_rmtauth�ṹ��Ϊȫ0ʱҲ�ɹ������ҹ���ģʽΪ�޼�Ȩģʽ
			 */
		}
		else
		{
			/*! �����û�������������֮һΪ�� */
			if (strRmtUsrName == NULL || strRmtPwd ==NULL)
			{
				if (errbuf != NULL)
				{
					memset(errbuf,0,PCAP_ERRBUF_SIZE);
					_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"Authentication mode is not eplicitly.UserName:[%s],Pwd:[%s]",strRmtUsrName,strRmtPwd);
				}
				return NPCAP_ERROR;
			}
			rmt_auth->type = RPCAP_RMTAUTH_PWD;
			rmt_auth->username = strRmtUsrName;
			rmt_auth->password = strRmtPwd;
		}		
	}

	return npcap_finddevs_internal(strSource,rmt_auth,interfaces,errbuf);	
}

NCGPCAP_API int npcap_freealldevs(npcap_if_t* interfaces)
{
	if (interfaces == NULL)
	{
		return NPCAP_SUCC;
	}
	
	pcap_freealldevs(NCGPCAP::local_if);
	for (npcap_if_t* cap_iterface = interfaces; cap_iterface != NULL; )
	{
		if (cap_iterface->ip != NULL)
		{
			delete cap_iterface->ip;
			cap_iterface->ip = NULL;
		}
		if (cap_iterface->netmask != NULL)
		{
			delete cap_iterface->netmask;
			cap_iterface->netmask = NULL;
		}
		npcap_if_t* tmpInterface = cap_iterface;
		cap_iterface = cap_iterface->next;
		delete tmpInterface;
	}
	return NPCAP_SUCC;
}

NCGPCAP_API int npcap_setdevs()
{
	return NPCAP_SUCC;
}

NCGPCAP_API int npcap_pcap_start(char* errbuf)
{

	if (npcap_getconfxml_internal(errbuf) == NPCAP_ERROR)
	{
		return NPCAP_ERROR;
	}
	return npcap_pcap_start_internal(errbuf);
}

NCGPCAP_API int npcap_pcap_stop()
{
	return NPCAP_SUCC;
}

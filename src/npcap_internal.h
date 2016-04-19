
/*!
 * \file npcap_internal.h
 *
 * \brief �Ȳ��������^�ļ���
 *
 * ԓ�ļ��������е��Ɍ�������ֱ���{�õăȲ�������
 * ���@Щ�����Ķ��x�����^�m�M�Ј���ģ�K�����롣
 * ԓ�ļ�������npcap_internal_def.h�����ɃȌӳ���ģ�K��
 */

#ifndef _NPCAP_INTERNAL_H_
#define _NPCAP_INTERNAL_H_

#include "pcap.h"

#include "npcap_internal_def.h"
#include "npcap_PCapUnit.h"

#define IPTOSBUFFERS	12


char*	iptos(u_long in);

std::string MakeCaptureOutputFileName(std::string strIp
                                      , int iPort
                                      , int iPortNum
                                      );


int		npcap_getconfxml_internal(char *errbuf);

int		npcap_finddevs_internal( char*				source
								, pcap_rmtauth*		rmt_auth
								, npcap_if**		alldevices
								, char*				errbuf
								);

int		npcap_pcap_start_internal(char* errbuf);

/*!
 * \brief ��һ��������ע��Cascade��ҵ���߼���ץ����Ԫ���ǣ�
 *
 * �ú�����ָ���������ϣ�����ҵ���߼��涨��rules, ��ҵ���߼���صĶ˿��Ͻ���һ��ץ����Ԫ������ʼץ����
 * Ŀǰ��˵����Щrules�У�sip�˿ڣ�client�˿ڣ���չץ���˿��Լ��Ƿ�ָ���Զ�ץȡ�ͶԶ�IP��ַ��
 *
 * \param interfaceInfo [IN] ����һ��ָ����������Ϣ��������Ϣ�а����Ϸ����������ƣ���ν�Ϸ������ܱ�pcap_openֱ��ʹ�õ��������ơ�
 * \param errbuf [OUT] ���ӿ�ʧ��ʱ���ش�����Ϣ����ָ����ָ�ռ����ⲿ���䣬�ҷ����С����С��256B, �������Խ����ʡ�
 *
 * \return ���ز�����ִ�н�������ڲ��κ�һ��ץ����Ԫִ��ʧ��ʱ�㷵��ʧ�ܣ�����errbuf�����з��ش�����Ϣ��
 *		   ��ִ��ʧ��ʱ���ڲ�ִ����ؽṹ�����ٲ�����
 *			- <B>0��NPCAP_SUCC��, ִ�гɹ�</B>
 *			- <B>-1��NPCAP_ERROR��, ִ��ʧ��</B>
 * \sa npcap_pcap_MakeMediaPCapUnits()
 */
int		npcap_pcap_MakeCascadePCapUnits(npcap_if_internal* interfaceInfo, char* errbuf);

/*!
 * \brief ��һ��������ע��Media��ҵ���߼���ץ����Ԫ���ǣ�
 *
 * �ú�����ָ���������ϣ�����ҵ���߼��涨��rules, ��ҵ���߼���صĶ˿��Ͻ���һ��ץ����Ԫ������ʼץ����
 * Ŀǰ��˵����Щrules�У�rtsp�˿ڣ��Ƿ�ָ���Զ�ץȡ���Զ�IP��ַ��udp�����俪ʼ�˿ڣ�udp������˿���Ŀ��
 *						rtsp�����䷢�Ϳ�ʼ�˿ڣ�rtsp�����䷢�Ͷ˿���Ŀ�� rtsp��������տ�ʼ�˿ڣ�rtsp��������ն˿���Ŀ��
 *
 * \param interfaceInfo [IN] ����һ��ָ����������Ϣ��������Ϣ�а����Ϸ����������ƣ���ν�Ϸ������ܱ�pcap_openֱ��ʹ�õ��������ơ�
 * \param errbuf [OUT] ���ӿ�ʧ��ʱ���ش�����Ϣ����ָ����ָ�ռ����ⲿ���䣬�ҷ����С����С��256B, �������Խ����ʡ�
 *
 * \return ���ز�����ִ�н�������ڲ��κ�һ��ץ����Ԫִ��ʧ��ʱ�㷵��ʧ�ܣ�����errbuf�����з��ش�����Ϣ��
 *		   ��ִ��ʧ��ʱ���ڲ�ִ����ؽṹ�����ٲ�����
 *			- <B>0��NPCAP_SUCC��, ִ�гɹ�</B>
 *			- <B>-1��NPCAP_ERROR��, ִ��ʧ��</B>
 */
int		npcap_pcap_MakeMediaPCapUnits(npcap_if_internal* interfaceInfo
									  , npcap_media* mediaInfo
									  , char* errbuf
									  );
/*!
 * �������������քe�ǣ�
 *	1. ץudp����ݔ�Ķ˿ڵİ���
 *	2. rtsp���ն˿ڵİ���
 *	3. rtsp�l�Ͷ˿ڵİ�
 * �����������һ��ֱ���]ጣ����@�ׂ��^�̷��ں����У�֮���޸ĳɸ�������_�J����ݔ�˿ڵİ汾�r�øġ�
 * 
 */
int		npcap_pcap_MakeMediaUdpStreamPCapUnits(npcap_if_internal* interfaceInfo
											, npcap_media* mediaInfo
											, char* errbuf
											);
int		npcap_pcap_MakeMediaRtspRecvPCapUnits(npcap_if_internal* interfaceInfo
										   , npcap_media* mediaInfo
										   , char* errbuf
										   );
int		npcap_pcap_MakeMediaRtspSendPCapUnits(npcap_if_internal* interfaceInfo
										   , npcap_media* mediaInfo
										   , char* errbuf
										   );


namespace NCGPCAP{
	/*!
	 * ���������������豸����
	 */
	extern pcap_if_t* g_local_if;

	/*!
	 * ץ����Ԫ����,�� npcap_pcap_MakeCascadePCapUnits() ���� �� npcap_pcap_MakeMediaPCapUnits() ������������
	 */
	extern std::list<CPcapUnit*> g_list_pcapUnits;
}

void    npcap_pcap_FreeAllPCapUnits();

#endif

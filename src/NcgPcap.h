
/*!
 * \file NcgPcap.h 
 *
 * \brief NcgPcap.dll�쌧�������^�ļ�
 *
 * ԓ�ļ����������еČ���������
 * �K��ԓ�����а���NcgPcap_def.h�ļ����������ģ�K��
 */

#ifndef _LIB_NCGPCAP_H_ 
#define _LIB_NCGPCAP_H_

#ifdef NCGPCAP_EXPORTS
#define NCGPCAP_API __declspec(dllexport)
#else
#define NCGPCAP_API __declspec(dllimport)
#endif

#include "NcgPcap_def.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief ��ȡ�����豸�ӿ�
 *
 * �ýӿں������ڷ���ָ�������������豸�ӿڣ��ڲ����б�����Զ�̻���������
 *
 * \param iIsLocal [IN] �Ƿ��Ǳ���������Ǳ���ץ��������remote��Ϣ������Ҫ���
 * \param strRmtIp [IN] Զ������IP��ַ����Զ��ץ��ʱ���˲�����ΪNULL
 * \param iRmtPort [IN] Զ������������pcap���ӵĶ˿ڣ�Ĭ��Ϊ2002����Զ��ץ��ʱ���˲�����ΪNULL
 * \param strRmtUsrName [IN] Զ��ץ�������Ȩ��Ϣ����ΪNULL����ʹ�ò���Ȩģʽ��������ץ��ʧ��
 * \param strRmtPwd [IN] Զ��ץ�������Ȩ��Ϣ����ΪNULL����ʹ�ò���Ȩģʽ��������ץ��ʧ��
 * \param interfaces [OUT] �ӿ���Ϣָ�룬�ڽӿ��ڲ�����ռ䣬���������豸�ӿ���Ϣ
 * \param errbuf [OUT]  ������Ϣ������������ʱ�ɴ˷��ش�����Ϣ���ռ����ⲿ���䣬�������ڵ���256B�Ŀռ�
 *
 * \return ���ؽӿڵ��ý����
 *			- <B>0���ɹ�</B>
 *			- <B>-1,ʧ��</B>��ʧ��ʱ����ͨ�����errbuf�����õ�������Ϣ
 */
NCGPCAP_API int npcap_findalldevs( int iIsLocal
								  , char* strRmtIp
								  , int iRmtPort
								  , char* strRmtUsrName
								  , char* strRmtPwd
								  , npcap_if_t **interfaces
								  , char* errbuf);

/*!
 * \brief ���������豸�ӿ�
 *
 * �ýӿں����������������豸�ӿڣ�Ϊ�����ڴ�й©����ÿ�ε���find֮ǰȷ��find��free�ӿ��Ѿ��ԳƵ���
 *
 * \param npcap_if_t [IN] npcap_findalldevs() �ӿڷ��ص��豸�б� 
 *
 * \return ���ؽӿڵ��ý����
 *			- <B>0���ɹ�</B>
 *			- <B>-1,ʧ��</B>��ʧ��ʱ����ͨ�����errbuf�����õ�������Ϣ
 */
NCGPCAP_API int npcap_freealldevs(npcap_if_t* interfaces);

/*!
 * \brief ��ʼץ��
 *
 * 
 */
NCGPCAP_API int npcap_pcap_start(char* errbuf);

NCGPCAP_API int npcap_pcap_stop();

#ifdef __cplusplus
}
#endif

#endif
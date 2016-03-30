// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� NCGPCAP_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// NCGPCAP_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifndef _LIB_NCGPCAP_H_ 
#define _LIB_NCGPCAP_H_

#ifdef NCGPCAP_EXPORTS
#define NCGPCAP_API __declspec(dllexport)
#else
#define NCGPCAP_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*! ���ú����ӿڳɹ�ʱ����ֵ */
#define NPCAP_SUCC 0
/*! ���ú����ӿ�ʧ��ʱ����ֵ */
#define NPCAP_ERROR -1

/*! ����ץ��ѡ����� npcap_findalldevs() �ӿڵĵ�һ������ */
#define LOCAL_CAPTURE 0
/*! Զ��ץ��ѡ����� npcap_findalldevs() �ӿڵĵ�һ������ */
#define REMOTE_CAPTURE 1

/*! errorBuf�Ĵ�С��256BYTES */
#define NPCAP_ERROR_BUFF_SIZE 256

typedef struct npcap_if npcap_if_t;

/*! 
 * \brief �����豸�ӿڽṹ��
 *
 * �ýṹ���������ⲿ���������豸�ӿ���Ϣ���Թ�����ץ���Ľӿ�ѡ��
 */
struct npcap_if
{
	struct npcap_if *next;		///< ��һ���ӿڵ�ָ��
	char *name;					///< �ӿ�����
	char *description;			///< �ӿ�����
	char *ip;					///< IP��ַ
	char *netmask;				///< ��������
};

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
NCGPCAP_API int npcap_findalldevs(int iIsLocal,char* strRmtIp, int iRmtPort, char* strRmtUsrName, char* strRmtPwd, npcap_if_t **interfaces, char* errbuf);

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
 * \brief ����ץ���������豸
 *
 * 
 */
NCGPCAP_API int npcap_setdevs();

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
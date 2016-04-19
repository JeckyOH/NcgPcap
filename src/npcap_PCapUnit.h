
/*!
 * \file npcap_PcapUnit.h
 *
 * \brief ץ����Ԫ���P�������x---ץ����Ԫģ�K��
 *
 * ԓģ�K���x��ץ����Ԫ�����Р���һ��ץ����Ԫ����ֻؓ؟һ���W���ϵ�һ���^�V�l����ץ����
 * ��춰���̎�����o��ӣ�
 * ��ԓ�ļ��У�����npcap_internal_def.h�����Ȳ����x�ė�Ϣ���������F�ļ��а���NcgPcap_def.hʹ�������L������һЩ���x��
 * ԓģ�K��ץ����Ԫģ�K��
 */

#ifndef _NPCAP_PCAPUNIT_H_
#define _NPCAP_PCAPUNIT_H_

#if (defined WIN32 || defined _WIN32 || defined WIN64 || defined _WIN64)
//#include <windows.h>
//#define strcpy strcpy_s;
//#define CALLBACK __stdcall
//#define NPCAP_HANDLE HANDLE 
//
typedef void *NPCAP_HANDLE;

#define NPCAP_INVALID_THREAD (NPCAP_HANDLE)(NULL) 

#else
///@Note Preserve for linux campatible.
#endif

#include "pcap.h"

#include "npcap_internal_def.h"


/*!
 *\brief ץ����Ԫ������ʵ��ץ��������ָ���ĺ��������
 */
class CPcapUnit
{
public:
	CPcapUnit();
	virtual ~CPcapUnit();

	virtual		std::string		GetInterfaceName()		const						{return m_strInterfaceName;}
	virtual		void			SetInterfaceName(const std::string& strIfName)		{m_strInterfaceName = strIfName;}

	virtual		std::string		GetFilterString()		const						{return m_strFilter;}
	virtual		void			SetFilterString(const std::string& strFilter)		{m_strFilter = strFilter;}

	virtual		std::string		GetOutputFileName()		const						{return m_strOutputFileName;}
	virtual		void			SetOutputFileName(const std::string& strOutputFileName)	{m_strOutputFileName = strOutputFileName;}

    virtual     std::string     GetNetMask()            const                       {return m_strNetMask;}
    virtual     void            SetNetMask(const std::string& strNetMask)           {m_strNetMask = strNetMask;}

	virtual		void			SetPacketHandler(npcap_handler cbPktHandler)		{m_cbPktHandler = cbPktHandler;}

	virtual		void			SetHandlerUserData(void *pUserData)					{m_pUserData = pUserData;}

	/*!
	 * \brief ��ʼץ��������
	 * 
	 * ���Ѿ����ú�����ӿ����ƣ�ץ�������ַ����ͻص�������ͨ�����øú�����ʼץ����
	 * �ڸú����У���������ץ�����̣߳����½��߳��н���ץ����
	 *
	 * \param rmt_info [IN] �����h�����C��Ϣ����ץ���C�İ��r��ԓ��������NULL����t��������NULLֵ�Kָ���h���B�ӵ���Ϣ��
	 * 
	 * \param errbuf [OUT] �����e�`��Ϣ�����g��С����Ҫ��256B����NPCAP_ERROR_BUFF_SIZE, ���g���{���߷���Kጷš�
	 *						���o�e�`�r�����g����memset��NULL��0��
	 * \return �����_ʼץ���ĽY�����ɹ���ʧ����
	 *		- <B>NPCAP_SUCC (= 0 )</B> , ץ���ɹ���errbuf���g�Ȕ�����NULL��
	 *		- <B>NPCAP_ERROR(= -1)</B> , ץ��ʧ����errbuf�Ƞ��e�`��Ϣ��
	 */
	virtual		int				StartCapture(npcap_rmt_info*	rmt_info, char*		errbuf);

	/*!
	 * \brief ��ʼץ��������
	 * 
	 * ԓ�����_ʼץ�������ÿ�����{�û��{�����M��̎��
	 *
	 */
	//virtual		void		StartHandlingPackets()								{m_bCapture = true;}

	virtual		void			capture_thread_function();
	/*!
	 * \brief ֹͣץ��������
	 * 
	 * �ڸú����У�ֹͣ����ץ�����̡߳�
	 *
	 * \param errbuf [IN] �����e�`��Ϣ�����g��С����Ҫ��256B����NPCAP_ERROR_BUFF_SIZE, ���g���{���߷���Kጷš�
	 *						���o�e�`�r�����g����memset��NULL��0��
	 * \return ����ֹͣץ���ĽY�����ɹ���ʧ����
	 *		- <B>NPCAP_SUCC (= 0 )</B> , ֹͣ�ɹ���errbuf���g�Ȕ�����NULL��
	 *		- <B>NPCAP_ERROR(= -1)</B> , ֹͣʧ����errbuf�Ƞ��e�`��Ϣ��
	 */
	virtual		int				StopCapture(char* errbuf);

private:
	std::string			m_strInterfaceName;			///< �����豸�ӿ����ƣ���pcap_findalldev_ex������ȡ���ġ�
	std::string			m_strFilter;				///< ץ���Ĺ����ַ�����Ҫ����pcap��Ĺ��˹���
	std::string			m_strNetMask;				///< �����gץ���^�V�l���r��Ҫ�õ�netmask
	std::string			m_strOutputFileName;		///< ����W�j�����ļ����Q,����Ĭ�J���ɣ�Ոָ��
	npcap_handler		m_cbPktHandler;				///< �ûص��������ⲿ�ṩ������ÿ���������øú�����������Ϊpcap_loop�����Ļص�����
	void				*m_pUserData;				///< ���������Ļص������д�����Զ������
	//bool				m_bCapture;					///< ���R�����_ʼץ����ԓ�_�P��춿��ƾ��̄����ɹ���ȴ��������̄����ɹ���
	//											///@Note ԓ׃���ȱ����š����ܲ��á�
	bool				m_bExist;					///< ���R���̵��\���c�Y�������̈��к�����Ҫ�M���Д࣬�����true�����ֹͣץ��				
	pcap_t				*m_pCapHandle;				///< ���_��ץ���������
	pcap_dumper_t		*m_pPktDumpHandle;			///< ����W�j�����ļ��ľ��

	NPCAP_HANDLE		m_hCaptureThread;			///< ץ���̵߳ľ��
};

#endif

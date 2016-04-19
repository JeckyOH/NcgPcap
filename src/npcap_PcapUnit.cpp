
#include "NcgPcap_def.h"
#include "npcap_PCapUnit.h"
#include <process.h>

/*!
 * \brief ���ַ�����͵�ip��ַ�D��unsigned int
 */
bpf_u_int32 strtoip(const char* ipStr)
{
	bpf_u_int32 ipInt = 0;
	u_char *p = (u_char*)&ipInt;
	sscanf(ipStr,"%d.%d.%d.%d",&p[0],&p[1],&p[2],&p[3]);
	return ipInt;
}

/*!
 * \brief ץ���̵߳����к�����
 *
 * �ڸú����У���ץ����Ԫץȡָ�������İ���ͨ��ָ���Ĺ����������˺󣬰�ÿ����ͨ���û����õ�handler�����ص����ⲿ���д���
 */
unsigned int CALLBACK npcap_thread_function(PVOID pParam)
{
	if (pParam == NULL)
	{
		return 1;
	}

	((CPcapUnit*)pParam)->capture_thread_function();

	return 0;
}


CPcapUnit::CPcapUnit()
: m_strInterfaceName("")
, m_strFilter("")
, m_strNetMask("")
, m_strOutputFileName("")
, m_cbPktHandler(NULL)
, m_pUserData(NULL)
//, m_bCapture(false)
, m_bExist(false)
, m_pCapHandle(NULL)
, m_pPktDumpHandle(NULL)
, m_hCaptureThread(NPCAP_INVALID_THREAD)
{
}

CPcapUnit::~CPcapUnit()
{
	this->StopCapture(NULL);

	if (m_hCaptureThread != NPCAP_INVALID_THREAD)
	{
		m_hCaptureThread = NPCAP_INVALID_THREAD;
	}
	if (m_pCapHandle != NULL)
	{
		m_pCapHandle = NULL;
	}
	if (m_pPktDumpHandle != NULL)
	{
		m_pPktDumpHandle = NULL;
	}
	if (m_pUserData != NULL)
	{
		m_pUserData = NULL;
	}
	if (m_cbPktHandler != NULL)
	{
		m_cbPktHandler = NULL;
	}
}

int		CPcapUnit::StartCapture(npcap_rmt_info*	rmt_info, char* errbuf)
{
	pcap_rmtauth RmtAuth;
	pcap_rmtauth *pRmtAuth = NULL;
	bpf_u_int32 netMask = 0xFFFFFF;
	struct bpf_program filterProgram;
	memset(&RmtAuth,0,sizeof(RmtAuth));
	memset(&filterProgram,0,sizeof(filterProgram));

	if (errbuf == NULL)
	{
		return NPCAP_ERROR;
	}
	memset(errbuf,0,NPCAP_ERROR_BUFF_SIZE);

	if (m_strInterfaceName.empty() || m_cbPktHandler == NULL || m_strOutputFileName.empty())
	{
		_snprintf(errbuf,NPCAP_ERROR_BUFF_SIZE-1,"At Least, the interface name, outputFileName and packet-handler is needed.");
		return NPCAP_ERROR;
	}

	if (m_strNetMask.empty() == false)
	{
		///��ԓ����CIP�Ƿ�Ϸ�
		netMask = strtoip(m_strNetMask.c_str());
	}

	//̎���a����Ϣ
	if (rmt_info != NULL)
	{
		if (rmt_info->rmt_auth_mode == NPCAP_RMT_AUTH_PWD)
		{
			RmtAuth.type = RPCAP_RMTAUTH_PWD;
			RmtAuth.username = rmt_info->rmt_auth_usrname;
			RmtAuth.password = rmt_info->rmt_auth_pwd;
		}
		else
		{
			RmtAuth.type = RPCAP_RMTAUTH_NULL;
		}
		pRmtAuth = &RmtAuth;
	}

	if ((m_pCapHandle = pcap_open(m_strInterfaceName.c_str(),	// name of the device
		65536,			// portion of the packet to capture. 
		1,				// promiscuous mode (nonzero means promiscuous)
		100,			// read timeout
		pRmtAuth,		// authentication information
		errbuf			// error buffer
		)) == NULL)
	{
		return NPCAP_ERROR;
	}

	if (m_strFilter.empty() == false)
	{
		if (
			(pcap_compile(m_pCapHandle,&filterProgram,m_strFilter.c_str(),1,netMask) < 0) 
			|| 
			(pcap_setfilter(m_pCapHandle,&filterProgram) < 0)
			)
		{
			strncpy(errbuf,pcap_geterr(m_pCapHandle),NPCAP_ERROR_BUFF_SIZE);
			pcap_close(m_pCapHandle);
			return NPCAP_ERROR;
		}
	}

	if ((m_pPktDumpHandle = pcap_dump_open(m_pCapHandle, m_strOutputFileName.c_str())) == NULL)
	{
		strncpy(errbuf,pcap_geterr(m_pCapHandle),NPCAP_ERROR_BUFF_SIZE);
		pcap_close(m_pCapHandle);
		return NPCAP_ERROR;
	}

	m_bExist = false;
	m_hCaptureThread = (HANDLE)_beginthreadex(NULL,0,npcap_thread_function,this,0,NULL);
	if (m_hCaptureThread == NPCAP_INVALID_THREAD)
	{
		_snprintf(errbuf,NPCAP_ERROR_BUFF_SIZE-1,"Create Thread Failed.InterfaceName:%s",m_strInterfaceName.c_str());
		pcap_close(m_pCapHandle);
		return NPCAP_ERROR;
	}
	
	return NPCAP_SUCC;
}

void	CPcapUnit::capture_thread_function()
{
	//while (m_bCapture == false);
	int						res = -1;			///< �@ȡ���ĽY��
	struct pcap_pkthdr		*pkt_header;		///< �@ȡ���Ĕ��������^��pcap�Լ������Ϣ�^�����ǰ��Ȳ��Ĕ�����
	const u_char			*pkt_data;			///< ������

	while (m_bExist != true)
	{
		if((res = pcap_next_ex( m_pCapHandle , &pkt_header, &pkt_data)) >= 0)
		{
			if(res == 0)
				/* �xȡ���r�r�g���ˣ��^�m�^�m */
				continue; 
			m_cbPktHandler(m_pUserData, m_pPktDumpHandle, pkt_header, pkt_data);
		}
	}
}

int		CPcapUnit::StopCapture(char* errbuf)
{
	if (m_bExist = true)
	{
		return NPCAP_SUCC;
	}

	m_bExist = true;
	WaitForSingleObject(m_hCaptureThread,INFINITE);
	pcap_close(m_pCapHandle);
	CloseHandle(m_hCaptureThread);

	return NPCAP_SUCC;
}
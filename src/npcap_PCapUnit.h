
/*!
 * \file npcap_PcapUnit.h
 *
 * \brief 抓包單元相關聲明及定義---抓包單元模塊。
 *
 * 該模塊定義了抓包單元及其行爲。一個抓包單元應當只負責一個網卡上的一個過濾條件的抓包，
 * 至於包的處理，交給外層！
 * 在該文件中，包含npcap_internal_def.h作爲內部定義的棲息場所，實現文件中包含NcgPcap_def.h使得其能訪問其中一些定義。
 * 該模塊爲抓包單元模塊。
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
 *\brief 抓包单元，负责实际抓包并调用指定的函数处理包
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
	 * \brief 开始抓包函数。
	 * 
	 * 在已经设置好网络接口名称，抓包过滤字符串和回调函数后，通过调用该函数开始抓包。
	 * 在该函数中，创建用于抓包的线程，在新建线程中进行抓包。
	 *
	 * \param rmt_info [IN] 傳入遠程主機信息，當抓本機的包時，該參數填入NULL，否則，應爲非NULL值並指明遠程連接的信息。
	 * 
	 * \param errbuf [OUT] 保存錯誤信息，空間大小至少要爲256B，即NPCAP_ERROR_BUFF_SIZE, 空間由調用者分配並釋放。
	 *						當無錯誤時，空間數據memset爲NULL（0）
	 * \return 返回開始抓包的結果：成功或失敗。
	 *		- <B>NPCAP_SUCC (= 0 )</B> , 抓包成功，errbuf空間內數據爲NULL。
	 *		- <B>NPCAP_ERROR(= -1)</B> , 抓包失敗，errbuf內爲錯誤信息。
	 */
	virtual		int				StartCapture(npcap_rmt_info*	rmt_info, char*		errbuf);

	/*!
	 * \brief 开始抓包函数。
	 * 
	 * 該函數開始抓包，對於每個包調用回調函數進行處理。
	 *
	 */
	//virtual		void		StartHandlingPackets()								{m_bCapture = true;}

	virtual		void			capture_thread_function();
	/*!
	 * \brief 停止抓包函数。
	 * 
	 * 在该函数中，停止用于抓包的线程。
	 *
	 * \param errbuf [IN] 保存錯誤信息，空間大小至少要爲256B，即NPCAP_ERROR_BUFF_SIZE, 空間由調用者分配並釋放。
	 *						當無錯誤時，空間數據memset爲NULL（0）
	 * \return 返回停止抓包的結果：成功或失敗。
	 *		- <B>NPCAP_SUCC (= 0 )</B> , 停止成功，errbuf空間內數據爲NULL。
	 *		- <B>NPCAP_ERROR(= -1)</B> , 停止失敗，errbuf內爲錯誤信息。
	 */
	virtual		int				StopCapture(char* errbuf);

private:
	std::string			m_strInterfaceName;			///< 网络设备接口名称，由pcap_findalldev_ex函数获取到的。
	std::string			m_strFilter;				///< 抓包的过滤字符串，要符合pcap库的过滤规则
	std::string			m_strNetMask;				///< 當編譯抓包過濾條件時候要用到netmask
	std::string			m_strOutputFileName;		///< 保存網絡包的文件名稱,不會默認生成，請指定
	npcap_handler		m_cbPktHandler;				///< 该回调函数由外部提供，对于每个包都调用该函数，或者作为pcap_loop函数的回调函数
	void				*m_pUserData;				///< 网络包处理的回调函数中传入的自定义参数
	//bool				m_bCapture;					///< 標識線程開始抓包，該開關用於控制線程創建成功後等待其他線程創建成功。
	//											///@Note 該變量先保留着。可能不用。
	bool				m_bExist;					///< 標識線程的運行與結束，線程執行函數中要進行判斷，如果爲true便代表停止抓包				
	pcap_t				*m_pCapHandle;				///< 打開的抓包實例句柄
	pcap_dumper_t		*m_pPktDumpHandle;			///< 保存網絡包到文件的句柄

	NPCAP_HANDLE		m_hCaptureThread;			///< 抓包线程的句柄
};

#endif

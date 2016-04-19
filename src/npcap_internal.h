
/*!
 * \file npcap_internal.h
 *
 * \brief 內部函數聲明頭文件。
 *
 * 該文件聲明了所有的由導出函數直接調用的內部函數。
 * 在這些函數的定義中再繼續進行執行模塊的深入。
 * 該文件包含了npcap_internal_def.h，構成內層抽象模塊。
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
 * \brief 在一个网卡上注册Cascade的业务逻辑的抓包单元（们）
 *
 * 该函数在指定的网卡上，根据业务逻辑规定的rules, 在业务逻辑相关的端口上建立一个抓包单元，并开始抓包。
 * 目前来说，这些rules有：sip端口，client端口，扩展抓包端口以及是否指定对端抓取和对端IP地址。
 *
 * \param interfaceInfo [IN] 给出一个指定的网卡信息，网卡信息中包括合法的网卡名称，所谓合法：即能被pcap_open直接使用的网卡名称。
 * \param errbuf [OUT] 当接口失败时返回错误信息，该指针所指空间由外部分配，且分配大小不得小于256B, 否则可能越界访问。
 *
 * \return 返回操作的执行结果，当内部任何一个抓包单元执行失败时便返回失败，并在errbuf参数中返回错误信息。
 *		   当执行失败时，内部执行相关结构的销毁操作。
 *			- <B>0（NPCAP_SUCC）, 执行成功</B>
 *			- <B>-1（NPCAP_ERROR）, 执行失败</B>
 * \sa npcap_pcap_MakeMediaPCapUnits()
 */
int		npcap_pcap_MakeCascadePCapUnits(npcap_if_internal* interfaceInfo, char* errbuf);

/*!
 * \brief 在一个网卡上注册Media的业务逻辑的抓包单元（们）
 *
 * 该函数在指定的网卡上，根据业务逻辑规定的rules, 在业务逻辑相关的端口上建立一个抓包单元，并开始抓包。
 * 目前来说，这些rules有：rtsp端口，是否指定对端抓取及对端IP地址，udp流传输开始端口，udp流传输端口数目，
 *						rtsp流传输发送开始端口，rtsp流传输发送端口数目， rtsp流传输接收开始端口，rtsp流传输接收端口数目。
 *
 * \param interfaceInfo [IN] 给出一个指定的网卡信息，网卡信息中包括合法的网卡名称，所谓合法：即能被pcap_open直接使用的网卡名称。
 * \param errbuf [OUT] 当接口失败时返回错误信息，该指针所指空间由外部分配，且分配大小不得小于256B, 否则可能越界访问。
 *
 * \return 返回操作的执行结果，当内部任何一个抓包单元执行失败时便返回失败，并在errbuf参数中返回错误信息。
 *		   当执行失败时，内部执行相关结构的销毁操作。
 *			- <B>0（NPCAP_SUCC）, 执行成功</B>
 *			- <B>-1（NPCAP_ERROR）, 执行失败</B>
 */
int		npcap_pcap_MakeMediaPCapUnits(npcap_if_internal* interfaceInfo
									  , npcap_media* mediaInfo
									  , char* errbuf
									  );
/*!
 * 下列三個函數分別是：
 *	1. 抓udp流傳輸的端口的包；
 *	2. rtsp接收端口的包；
 *	3. rtsp發送端口的包
 * 爲了日後可以一併直接註釋，將這幾個過程放在函數中，之後修改成根據信令確認流傳輸端口的版本時好改。
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
	 * 本地主机的网络设备集合
	 */
	extern pcap_if_t* g_local_if;

	/*!
	 * 抓包单元集合,被 npcap_pcap_MakeCascadePCapUnits() 函数 和 npcap_pcap_MakeMediaPCapUnits() 函数所操作。
	 */
	extern std::list<CPcapUnit*> g_list_pcapUnits;
}

void    npcap_pcap_FreeAllPCapUnits();

#endif

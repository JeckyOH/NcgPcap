
/*!
 * \file NcgPcap.h 
 *
 * \brief NcgPcap.dll庫導出函數頭文件
 *
 * 該文件中聲明了所有的導出函數。
 * 並在該函數中包含NcgPcap_def.h文件。構成外圍模塊。
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
 * \brief 获取网络设备接口
 *
 * 该接口函数用于返回指定机器的网络设备接口，内部进行本机和远程机器的区分
 *
 * \param iIsLocal [IN] 是否是本机，如果是本机抓包，随后的remote信息都不需要检测
 * \param strRmtIp [IN] 远程主机IP地址，当远程抓包时，此参数不为NULL
 * \param iRmtPort [IN] 远程主机上用于pcap连接的端口，默认为2002，当远程抓包时，此参数不为NULL
 * \param strRmtUsrName [IN] 远程抓包所需鉴权信息，若为NULL，则使用不鉴权模式，但可能抓包失败
 * \param strRmtPwd [IN] 远程抓包所需鉴权信息，若为NULL，则使用不鉴权模式，但可能抓包失败
 * \param interfaces [OUT] 接口信息指针，在接口内部分配空间，返回网络设备接口信息
 * \param errbuf [OUT]  错误信息，当发生错误时由此返回错误信息，空间由外部分配，请分配大于等于256B的空间
 *
 * \return 返回接口调用结果：
 *			- <B>0，成功</B>
 *			- <B>-1,失败</B>，失败时可以通过检查errbuf参数得到错误信息
 */
NCGPCAP_API int npcap_findalldevs( int iIsLocal
								  , char* strRmtIp
								  , int iRmtPort
								  , char* strRmtUsrName
								  , char* strRmtPwd
								  , npcap_if_t **interfaces
								  , char* errbuf);

/*!
 * \brief 销毁网络设备接口
 *
 * 该接口函数用于销毁网络设备接口，为避免内存泄漏，请每次调用find之前确保find和free接口已经对称调用
 *
 * \param npcap_if_t [IN] npcap_findalldevs() 接口返回的设备列表 
 *
 * \return 返回接口调用结果：
 *			- <B>0，成功</B>
 *			- <B>-1,失败</B>，失败时可以通过检查errbuf参数得到错误信息
 */
NCGPCAP_API int npcap_freealldevs(npcap_if_t* interfaces);

/*!
 * \brief 开始抓包
 *
 * 
 */
NCGPCAP_API int npcap_pcap_start(char* errbuf);

NCGPCAP_API int npcap_pcap_stop();

#ifdef __cplusplus
}
#endif

#endif
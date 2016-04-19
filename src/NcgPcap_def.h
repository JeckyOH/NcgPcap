
/*!
 * \file NcgPcap_def.h
 *
 * \brief NcgPcap.dll導出變量等定義頭文件。
 *
 * 該頭文件定義了所有的NcgPcap.dll庫的導出變量、類型以及宏的定義。
 * 該頭文件被NcgPcap.h頭文件包含。
 *
 */

#ifndef _NCGPCAP_DEF_H_
#define _NCGPCAP_DEF_H_

/*! 调用函数接口成功时返回值 */
#define NPCAP_SUCC			0
/*! 调用函数接口失败时返回值 */
#define NPCAP_ERROR			-1

/*! 本机抓包选项，用于 npcap_findalldevs() 接口的第一个参数 */
#define LOCAL_CAPTURE		0
/*! 远程抓包选项，用于 npcap_findalldevs() 接口的第一个参数 */
#define REMOTE_CAPTURE		1

/*! errorBuf的大小：256BYTES */
#define NPCAP_ERROR_BUFF_SIZE 256

/*! 
 * \brief 网络设备接口结构体
 *
 * 该结构体用于向外部传递网络设备接口信息，以供进行抓包的接口选择。
 */
typedef	struct npcap_if	npcap_if_t;

#endif
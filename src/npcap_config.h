
/*!
 * \file npcap_config.h
 *
 * \brief 全局配置模塊（全局變量模塊）
 *
 * 該模塊中保存了所有的全局變量，包括從頁面生成的配置文件npcap.conf.xml中讀取的。
 * 其中包含：信令網關抓包相關，媒體網關抓包相關，抓包文件中間保存路徑等。
 * 抓包相關指的是：對於本地抓包：抓包網卡名稱，抓包的各個協議對應的端口等；
 *				對於遠程媒體網關抓包，遠程主機ip,鑑權信息，網卡名稱，各個協議對應的端口及媒體流端口範圍等。
 */

#ifndef _NPCAP_CONFIG_H_
#define _NPCAP_CONFIG_H_

#include <string>
#include <list>
#include <vector>

#include "npcap_internal_def.h"

using namespace std;

namespace CONFIG{

	bool					g_bOppositeCap = false;				///< 是否指定对端抓取
	char					g_szOppositeIp[16] = {0};			///< 对端抓取IP
	list<npcap_if_internal> g_cascIfList;						///< 信令网关网络设备接口列表
	int						g_iSipPort = 0;						///< 信令网关SIP端口
	int						g_iClientPort = 0;					///< 信令网关客户端端口
	vector<int>				g_cascExtendPortList;				///< 信令网关抓包扩展端口
	list<npcap_media>		g_mediaList;						///< 媒体网关列表
	string					g_strWorkingDirectory;				///< 工作目录，最后打包工作目录里面的内容
}

#endif

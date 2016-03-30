// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 NCGPCAP_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// NCGPCAP_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
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

/*! 调用函数接口成功时返回值 */
#define NPCAP_SUCC 0
/*! 调用函数接口失败时返回值 */
#define NPCAP_ERROR -1

/*! 本机抓包选项，用于 npcap_findalldevs() 接口的第一个参数 */
#define LOCAL_CAPTURE 0
/*! 远程抓包选项，用于 npcap_findalldevs() 接口的第一个参数 */
#define REMOTE_CAPTURE 1

/*! errorBuf的大小：256BYTES */
#define NPCAP_ERROR_BUFF_SIZE 256

typedef struct npcap_if npcap_if_t;

/*! 
 * \brief 网络设备接口结构体
 *
 * 该结构体用于向外部传递网络设备接口信息，以供进行抓包的接口选择。
 */
struct npcap_if
{
	struct npcap_if *next;		///< 下一个接口的指针
	char *name;					///< 接口名称
	char *description;			///< 接口描述
	char *ip;					///< IP地址
	char *netmask;				///< 子网掩码
};

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
NCGPCAP_API int npcap_findalldevs(int iIsLocal,char* strRmtIp, int iRmtPort, char* strRmtUsrName, char* strRmtPwd, npcap_if_t **interfaces, char* errbuf);

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
 * \brief 设置抓包的网络设备
 *
 * 
 */
NCGPCAP_API int npcap_setdevs();

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
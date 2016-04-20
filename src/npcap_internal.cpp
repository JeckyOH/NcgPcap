#include "markup.h"

#include "NcgPcap_def.h"
#include "npcap_internal.h"
#include "npcap_config.h"
#include "npcap_pkt_handlers.h"

using namespace std;

pcap_if_t* NCGPCAP::g_local_if;
list<CPcapUnit*> NCGPCAP::g_list_pcapUnits;

/*!
 * \brief 把unsigned int 類型的ip地址轉爲字符串
 */
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

std::string MakeCaptureOutputFileName(std::string strIp
                                      , int iPort
                                      , int iPortNum)
{
    char fileName[1024] = {0};

	_snprintf(fileName, 1023, "%s\\Interface(%s)port(%d)portNum(%d)", CONFIG::g_strWorkingDirectory.c_str(), strIp.c_str(), iPort, iPortNum);

    return string(fileName);
}

int npcap_finddevs_internal(char* source, pcap_rmtauth* rmt_auth,npcap_if** alldevices,char* errbuf)
{
	char err_buf[PCAP_BUF_SIZE] = {0};
	if(pcap_findalldevs_ex(source,rmt_auth,&NCGPCAP::g_local_if,err_buf) == -1)
	{
		if (errbuf != NULL)
		{
			memcpy(errbuf,err_buf,NPCAP_ERROR_BUFF_SIZE);
		}
		return NPCAP_ERROR;
	}
	//组装回复信息
	pcap_if_t* pcap_interface = NULL;
	npcap_if_t* npcap_interface = NULL;
	npcap_if_t* npcap_interface_head = NULL;
	npcap_if_t* npcap_interface_tail = NULL;

	for (pcap_interface = NCGPCAP::g_local_if;pcap_interface != NULL; pcap_interface = pcap_interface->next)
	{
		npcap_interface = new npcap_if_t;
		if (npcap_interface == NULL)
		{
			if (errbuf != NULL)
			{
				_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"allocate memory failed.");
				return NPCAP_ERROR;
			}
		}
		memset(npcap_interface,0,sizeof(npcap_if_t));
		npcap_interface->name = pcap_interface->name;
		npcap_interface->description = pcap_interface->description;
		
		for(pcap_addr_t* addr=pcap_interface->addresses;addr;addr=addr->next)
		{
			if(addr->addr->sa_family == AF_INET)
			{
				if (addr->addr != NULL)
				{
					npcap_interface->ip = new char[16];
					if (npcap_interface->ip == NULL)
					{
						if (errbuf != NULL)
						{
							_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"allocate memory failed.");
							return NPCAP_ERROR;
						}
					}
					memset(npcap_interface->ip,0,16);
					strcpy(npcap_interface->ip,iptos(((struct sockaddr_in *)addr->addr)->sin_addr.s_addr));
				}
				if (addr->netmask != NULL)
				{
					npcap_interface->netmask = new char[16];
					if (npcap_interface->netmask == NULL)
					{
						if (errbuf != NULL)
						{
							_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"allocate memory failed.");
							return NPCAP_ERROR;
						}
					}
					memset(npcap_interface->netmask,0,16);
					strcpy(npcap_interface->netmask,iptos(((struct sockaddr_in *)addr->netmask)->sin_addr.s_addr));
				}
				break;
			}
		}
		if (npcap_interface_head == NULL)
		{
			npcap_interface_head = npcap_interface;
			npcap_interface_tail = npcap_interface;
		}
		else
		{
			npcap_interface_tail->next = npcap_interface;
			npcap_interface_tail = npcap_interface_tail->next;
		}
	}

	if (npcap_interface_head != NULL)
	{
		*alldevices = npcap_interface_head;
	}
	else
	{
		*alldevices = NULL;
		if (errbuf != NULL)
		{
			_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"find none devices.");
			return NPCAP_ERROR;
		}
	}

	return NPCAP_SUCC;
}

int npcap_getconfxml_internal(char *errbuf)
{
	CMarkupSTL cXml;
	string errElement = "";

	if (errbuf != NULL)
	{
		memset(errbuf,0,PCAP_ERRBUF_SIZE);
	}

	if (cXml.Load(".\\npcap.conf.xml") == false)
	{
		if (errbuf != NULL)
		{
			_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"Load npcap.conf.xml Failed. Please check if this file exists.");
		}
		return NPCAP_ERROR;
	}

	do 
	{
		if(cXml.FindElem("NpcapConfigure") == false)
		{
			errElement = "NpcapConfigure";
			break;
		}
		cXml.IntoElem();

		if (cXml.FindElem("PacketCaptureConfigure",true) == false)
		{
			errElement = "PacketCaptureConfigure";
			break;
		}
		cXml.IntoElem();	//PacketCaptureConfigure

		if (cXml.FindElem("OppositeCap",true) == false)
		{
			errElement = "OppositeCap";
			break;
		}
		CONFIG::g_bOppositeCap = cXml.GetData()=="0"?false:true;
		if (CONFIG::g_bOppositeCap == true)
		{
			if (cXml.FindElem("OppositeIp",true) == false)
			{
				errElement = "OppositeIp";
				break;
			}
		}
		strncpy(CONFIG::g_szOppositeIp,cXml.GetData().c_str(),15);
		if (cXml.FindElem("CascadeConfigure",true) == false)
		{
			errElement = "CascadeConfigure";
			break;
		}
		cXml.IntoElem();	//CascadeConfigure
		if (cXml.FindElem("DeviceList",true) == false)
		{
			errElement = "DeviceList";
			break;
		}
		cXml.IntoElem();	//DeviceList
		CONFIG::g_cascIfList.clear();
		while(cXml.FindElem("Item"))
		{
			npcap_if_internal ifItem;
			ifItem.if_name = cXml.GetData();
			ifItem.if_ip = cXml.GetAttrib("ip");
			ifItem.if_netmask = cXml.GetAttrib("netmask");
			CONFIG::g_cascIfList.push_back(ifItem);
		}
		cXml.OutOfElem();	//DeviceList
		if (cXml.FindElem("SipPort",true) == false)
		{
			errElement = "SipPort";
			break;
		}
		CONFIG::g_iSipPort = atoi(cXml.GetData().c_str());

		if (cXml.FindElem("ClientPort",true) == false)
		{
			errElement = "ClientPort";
			break;
		}
		CONFIG::g_iClientPort = atoi(cXml.GetData().c_str());
		if (cXml.FindElem("PortablePortList",true) == false)
		{
			errElement = "PortablePortList";
			break;
		}
		cXml.IntoElem();	//PortablePortList
		while(cXml.FindElem("Item"))
		{
			CONFIG::g_cascExtendPortList.push_back(atoi(cXml.GetData().c_str()));
		}
		cXml.OutOfElem();	//PortablePortList
		cXml.OutOfElem();	//CascadeConfigure

		if (cXml.FindElem("MediaConfigure",true) == false)
		{
			errElement = "MediaConfigure";
			break;
		}
		cXml.IntoElem();	//MediaConfigure

		if (cXml.FindElem("LocalMedia",true))
		{
			/* 本地媒体网关最多能有一个，且可以没有,个数限制放在前端，后端不判断 */
			cXml.IntoElem();	//LocalMedia
			npcap_media media;
			media.iMediaPosition = NPCAP_MEDIA_LOCAL;

			if (cXml.FindElem("DeviceList",true) == false)
			{
				errElement = "DeviceList";
				break;
			}
			cXml.IntoElem();			//DeviceList
			while (cXml.FindElem("Item"))
			{
				npcap_if_internal ifItem;
				ifItem.if_name = cXml.GetData();
				ifItem.if_ip = cXml.GetAttrib("ip");
				ifItem.if_netmask = cXml.GetAttrib("netmask");
				media.listInterfaces.push_back(ifItem);
			}
			cXml.OutOfElem();			//DeviceList

			if (cXml.FindElem("RtspPort",true) == false)
			{
				errElement = "RtspPort";
				break;
			}
			media.iRtspPort = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("UdpPortBase",true) == false)
			{
				errElement = "UdpPortBase";
				break;
			}
			media.iUdpPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("UdpPortNum",true) == false)
			{
				errElement = "UdpPortNum";
				break;
			}
			media.iUdpPortNum = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspSendPortBase",true) == false)
			{
				errElement = "RtspSendPortBase";
				break;
			}
			media.iRtspSendPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspSendPortNum",true) == false)
			{
				errElement = "RtspSendPortNum";
				break;
			}
			media.iRtspSendPortNum = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspRecvPortBase",true) == false)
			{
				errElement = "RtspRecvPortBase";
				break;
			}
			media.iRtspRecvPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspRecvPortNum",true) == false)
			{
				errElement = "RtspRecvPortNum";
				break;
			}
			media.iRtspRecvPortNum = atoi(cXml.GetData().c_str());

			cXml.OutOfElem();	//Media
			CONFIG::g_mediaList.push_back(media);
		}

		bool xmlError = false; //标识在下面循环中是否有错误
		while (cXml.FindElem("RemoteMedia"))
		{
			cXml.IntoElem();	//RemoteMedia
			/* 远程媒体网关可以有任意个 */
			npcap_media media;

			media.iMediaPosition = NPCAP_MEDIA_REMOTE;
			
			if (cXml.FindElem("ConnectIp",true) == false)
			{
				errElement = "ConnectIp";
				xmlError = true;
				break;
			}
			media.strRmtIp = cXml.GetData();
			if (cXml.FindElem("ConnectPort",true) == false)
			{
				errElement = "ConnectPort";
				xmlError = true;
				break;
			}
			media.iRmtPort = atoi(cXml.GetData().c_str());
			if (cXml.FindElem("Authentication",true) == false)
			{
				errElement = "Authentication";
				xmlError = true;
				break;
			}
			media.iRemoteAuthMode = REMOTE_AUTH_MODE(cXml.GetAttrib("use")=="0"?0:1);
			if (media.iRemoteAuthMode == NPCAP_RMT_AUTH_PWD)
			{
				cXml.IntoElem();		//Authentication
				if (cXml.FindElem("UserName",true) == false)
				{
					errElement = "UserName";
					xmlError = true;
					break;
				}
				media.strRmtAuthUsrName = cXml.GetData();
				if (cXml.FindElem("PassWord",true) == false)
				{
					errElement = "PassWord";
					xmlError = true;
					break;
				}
				media.strRmtAuthPwd = cXml.GetData();
				cXml.OutOfElem();		//Authentication
			}

			if (cXml.FindElem("DeviceList",true) == false)
			{
				errElement = "DeviceList";
				xmlError = true;
				break;
			}
			cXml.IntoElem();			//DeviceList
			while (cXml.FindElem("Item"))
			{
				npcap_if_internal ifItem;
				ifItem.if_name = cXml.GetData();
				ifItem.if_ip = cXml.GetAttrib("ip");
				ifItem.if_netmask = cXml.GetAttrib("netmask");
				media.listInterfaces.push_back(ifItem);
			}
			cXml.OutOfElem();			//DeviceList

			if (cXml.FindElem("RtspPort",true) == false)
			{
				errElement = "RtspPort";
				xmlError = true;
				break;
			}
			media.iRtspPort = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("UdpPortBase",true) == false)
			{
				errElement = "UdpPortBase";
				xmlError = true;
				break;
			}
			media.iUdpPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("UdpPortNum",true) == false)
			{
				errElement = "UdpPortNum";
				xmlError = true;
				break;
			}
			media.iUdpPortNum = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspSendPortBase",true) == false)
			{
				errElement = "RtspSendPortBase";
				xmlError = true;
				break;
			}
			media.iRtspSendPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspSendPortNum",true) == false)
			{
				errElement = "RtspSendPortNum";
				xmlError = true;
				break;
			}
			media.iRtspSendPortNum = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspRecvPortBase",true) == false)
			{
				errElement = "RtspRecvPortBase";
				xmlError = true;
				break;
			}
			media.iRtspRecvPortBase = atoi(cXml.GetData().c_str());

			if (cXml.FindElem("RtspRecvPortNum",true) == false)
			{
				errElement = "RtspRecvPortNum";
				xmlError = true;
				break;
			}
			media.iRtspRecvPortNum = atoi(cXml.GetData().c_str());

			cXml.OutOfElem();	//RemoteMedia
			CONFIG::g_mediaList.push_back(media);
		}
		if (xmlError == true)
		{
			break;
		}

		cXml.OutOfElem();	//MediaConfigure

		if (cXml.FindElem("WorkingDirectory",true) == false)
		{
			errElement = "WorkingDirectory";
			break;
		}
		CONFIG::g_strWorkingDirectory = cXml.GetData();

		cXml.OutOfElem();	//PacketCaptureConfigure

		cXml.OutOfElem();
		return NPCAP_SUCC;
	} while (0);
	if (errbuf != NULL)
	{
		_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"Has not find [%s] element in npcap.conf.xml.",errElement.c_str());
	}
	return NPCAP_ERROR;
}

int npcap_pcap_start_internal(char* errbuf)
{
    list<npcap_if_internal>::iterator itIf = CONFIG::g_cascIfList.begin();
    list<npcap_media>::iterator itMedia = CONFIG::g_mediaList.begin();

    for (; itIf != CONFIG::g_cascIfList.end();itIf++)
    {
        if(npcap_pcap_MakeCascadePCapUnits(&(*itIf), errbuf) == NPCAP_ERROR)
        {
			npcap_pcap_FreeAllPCapUnits();
            return NPCAP_ERROR;
        }
    }

    for (; itMedia != CONFIG::g_mediaList.end(); itMedia++)
    {
        for(itIf = itMedia->listInterfaces.begin(); itIf != itMedia->listInterfaces.end(); itIf++)
        {
            if(NPCAP_ERROR == npcap_pcap_MakeMediaPCapUnits(&(*itIf), &(*itMedia), errbuf))
            {
				npcap_pcap_FreeAllPCapUnits();
                return NPCAP_ERROR;
            }
        }
    }

    return NPCAP_SUCC;
}

int npcap_pcap_MakeCascadePCapUnits(npcap_if_internal* interfaceInfo, char* errbuf)
{
    if(errbuf == NULL)
    {
        return NPCAP_ERROR;
    }
    CPcapUnit* pPcapUnit = NULL;
    char strFilterPrefix[256] = {0};
    char strFilterTmp[256] = {0};
    int portTmp = 0;

    if (CONFIG::g_bOppositeCap == true)
    {
        _snprintf(strFilterPrefix,255,"host %s and", CONFIG::g_szOppositeIp);
    }

    for(int i = 0; i < (CONFIG::g_cascExtendPortList.size() + 1 + 1); i++)
    {
		pPcapUnit = new CPcapUnit;
		if (pPcapUnit == NULL) 
		{
		    _snprintf(errbuf, NPCAP_ERROR_BUFF_SIZE-1, "Allocate Space for Capture Unit Failed.");
		    return NPCAP_ERROR;
		}
        if (i < 2) //Indicating that we are create capture unit for sip port and client port 
        {
            if (i == 0) //Sip Port
            {
                portTmp = CONFIG::g_iSipPort;
            }
            else
            {
                portTmp = CONFIG::g_iClientPort;
            }
			if (portTmp == -1 || portTmp == 0)
			{
				continue;
			}
        }
        else
        {
            portTmp = CONFIG::g_cascExtendPortList[i - 2];
        }
		_snprintf(strFilterTmp, 255, "%s port %d", strFilterPrefix, portTmp);
		pPcapUnit->SetInterfaceName(interfaceInfo->if_name);
		pPcapUnit->SetFilterString(string(strFilterTmp));
		pPcapUnit->SetOutputFileName(MakeCaptureOutputFileName(interfaceInfo->if_ip, portTmp, 1));
		pPcapUnit->SetNetMask(interfaceInfo->if_netmask);
		pPcapUnit->SetPacketHandler(pkt_handler_DumpToFile); //This should not be NULL.
		if (pPcapUnit->StartCapture(NULL, errbuf) == NPCAP_ERROR) 
		{
		    delete pPcapUnit;
		    return NPCAP_ERROR;
		}
    	NCGPCAP::g_list_pcapUnits.push_back(pPcapUnit);
        pPcapUnit = NULL;
        portTmp = 0;
    }
    return NPCAP_SUCC;
}

int npcap_pcap_MakeMediaPCapUnits(npcap_if_internal* interfaceInfo, npcap_media* mediaInfo, char* errbuf)
{
    if (errbuf == NULL)
    {
        return NPCAP_ERROR;
    }
    CPcapUnit* pPcapUnit = NULL;
    char strFilterPrefix[256] = {0};
    char strFilterTmp[256] = {0};
	npcap_rmt_info *pRmtInfo = NULL, RmtInfo;
	memset(&RmtInfo,0,sizeof(RmtInfo));

    if (CONFIG::g_bOppositeCap == true)
    {
        _snprintf(strFilterPrefix,255,"host %s and", CONFIG::g_szOppositeIp);
    }

    pPcapUnit = new CPcapUnit;
    if (pPcapUnit == NULL)
    {
        _snprintf(errbuf, NPCAP_ERROR_BUFF_SIZE-1, "Allocate space for Capture Unit Failed.");
        return NPCAP_ERROR;
    }

    _snprintf(strFilterTmp, 255, "%s port %d", strFilterPrefix, mediaInfo->iRtspPort);
    pPcapUnit->SetFilterString(string(strFilterTmp));
    pPcapUnit->SetInterfaceName(interfaceInfo->if_name);
    pPcapUnit->SetNetMask(interfaceInfo->if_netmask);
    pPcapUnit->SetOutputFileName(MakeCaptureOutputFileName(interfaceInfo->if_ip, mediaInfo->iRtspPort, 1));
    pPcapUnit->SetPacketHandler(pkt_handler_DumpToFile); //This should not be NULL.
    if (mediaInfo->iMediaPosition == NPCAP_MEDIA_REMOTE) 
    {
		 strncpy(RmtInfo.rmt_ip,mediaInfo->strRmtIp.c_str(),mediaInfo->strRmtIp.size());
		 RmtInfo.rmt_port = mediaInfo->iRmtPort;
		 RmtInfo.rmt_auth_mode = int(mediaInfo->iRemoteAuthMode);
		 strncpy(RmtInfo.rmt_auth_usrname, mediaInfo->strRmtAuthUsrName.c_str(), mediaInfo->strRmtAuthUsrName.size());
		 strncpy(RmtInfo.rmt_auth_pwd, mediaInfo->strRmtAuthPwd.c_str(), mediaInfo->strRmtAuthPwd.size());
		 pRmtInfo = &RmtInfo;
    }
    if (pPcapUnit->StartCapture(pRmtInfo, errbuf) == NPCAP_ERROR)
    {
        delete pPcapUnit;
        return NPCAP_ERROR;
    }
    NCGPCAP::g_list_pcapUnits.push_back(pPcapUnit);

    /* Udp Rtsp are another three functions,
     * considering we are going to modify the logic about captureing stream Packets later.
     */
    if(NPCAP_ERROR == npcap_pcap_MakeMediaUdpStreamPCapUnits(interfaceInfo, mediaInfo, errbuf))
    {
        return NPCAP_ERROR;
    }
    if(NPCAP_ERROR == npcap_pcap_MakeMediaRtspRecvPCapUnits(interfaceInfo, mediaInfo, errbuf))
    {
        return NPCAP_ERROR;
    }
    if(NPCAP_ERROR == npcap_pcap_MakeMediaRtspSendPCapUnits(interfaceInfo, mediaInfo, errbuf))
    {
        return NPCAP_ERROR;
    }

    return NPCAP_SUCC;
}

int npcap_pcap_MakeMediaUdpStreamPCapUnits(npcap_if_internal* interfaceInfo, npcap_media* mediaInfo, char* errbuf)
{
    if (errbuf == NULL)
    {
        return NPCAP_ERROR;
    }
    CPcapUnit* pPcapUnit = NULL;
    char strFilterTmp[256] = {0};
	npcap_rmt_info *pRmtInfo = NULL, RmtInfo;
	memset(&RmtInfo,0,sizeof(RmtInfo));

    pPcapUnit = new CPcapUnit;
    if (pPcapUnit == NULL)
    {
        _snprintf(errbuf, NPCAP_ERROR_BUFF_SIZE-1, "Allocate space for Capture Unit Failed.");
        return NPCAP_ERROR;
    }

	_snprintf(strFilterTmp, 255, "(udp[0:2] >= %d && udp[0:2] < %d) || (udp[2:2] >= %d && udp[2:2] < %d) "
		, mediaInfo->iUdpPortBase
		, mediaInfo->iUdpPortBase + 2 * mediaInfo->iUdpPortNum
		, mediaInfo->iUdpPortBase
		, mediaInfo->iUdpPortBase + 2 * mediaInfo->iUdpPortNum
		);
    pPcapUnit->SetFilterString(string(strFilterTmp));
    pPcapUnit->SetInterfaceName(interfaceInfo->if_name);
    pPcapUnit->SetNetMask(interfaceInfo->if_netmask);
    pPcapUnit->SetOutputFileName(MakeCaptureOutputFileName(interfaceInfo->if_ip, mediaInfo->iUdpPortBase, mediaInfo->iUdpPortNum));
    pPcapUnit->SetPacketHandler(pkt_handler_DumpToFile); //This should not be NULL.
    if (mediaInfo->iMediaPosition == NPCAP_MEDIA_REMOTE) 
    {
		 strncpy(RmtInfo.rmt_ip,mediaInfo->strRmtIp.c_str(),mediaInfo->strRmtIp.size());
		 RmtInfo.rmt_port = mediaInfo->iRmtPort;
		 RmtInfo.rmt_auth_mode = int(mediaInfo->iRemoteAuthMode);
		 strncpy(RmtInfo.rmt_auth_usrname, mediaInfo->strRmtAuthUsrName.c_str(), mediaInfo->strRmtAuthUsrName.size());
		 strncpy(RmtInfo.rmt_auth_pwd, mediaInfo->strRmtAuthPwd.c_str(), mediaInfo->strRmtAuthPwd.size());
		 pRmtInfo = &RmtInfo;
    }
    if (pPcapUnit->StartCapture(pRmtInfo, errbuf) == NPCAP_ERROR)
    {
        delete pPcapUnit;
        return NPCAP_ERROR;
    }
    NCGPCAP::g_list_pcapUnits.push_back(pPcapUnit);

    return NPCAP_SUCC;
}
int npcap_pcap_MakeMediaRtspRecvPCapUnits(npcap_if_internal* interfaceInfo, npcap_media* mediaInfo, char* errbuf)
{
	if (errbuf == NULL)
	{
		return NPCAP_ERROR;
	}
	CPcapUnit* pPcapUnit = NULL;
	char strFilterTmp[256] = {0};
	npcap_rmt_info *pRmtInfo = NULL, RmtInfo;
	memset(&RmtInfo,0,sizeof(RmtInfo));

	pPcapUnit = new CPcapUnit;
	if (pPcapUnit == NULL)
	{
		_snprintf(errbuf, NPCAP_ERROR_BUFF_SIZE-1, "Allocate space for Capture Unit Failed.");
		return NPCAP_ERROR;
	}

	_snprintf(strFilterTmp, 255, "tcp[2:2] >= %d && tcp[2:2] < %d"
		, mediaInfo->iRtspRecvPortBase
		, mediaInfo->iRtspRecvPortBase + 2 * mediaInfo->iRtspRecvPortNum
		);
	pPcapUnit->SetFilterString(string(strFilterTmp));
	pPcapUnit->SetInterfaceName(interfaceInfo->if_name);
	pPcapUnit->SetNetMask(interfaceInfo->if_netmask);
	pPcapUnit->SetOutputFileName(MakeCaptureOutputFileName(interfaceInfo->if_ip, mediaInfo->iRtspRecvPortBase, mediaInfo->iRtspRecvPortNum));
	pPcapUnit->SetPacketHandler(pkt_handler_DumpToFile); //This should not be NULL.
	if (mediaInfo->iMediaPosition == NPCAP_MEDIA_REMOTE) 
	{
		strncpy(RmtInfo.rmt_ip,mediaInfo->strRmtIp.c_str(),mediaInfo->strRmtIp.size());
		RmtInfo.rmt_port = mediaInfo->iRmtPort;
		RmtInfo.rmt_auth_mode = int(mediaInfo->iRemoteAuthMode);
		strncpy(RmtInfo.rmt_auth_usrname, mediaInfo->strRmtAuthUsrName.c_str(), mediaInfo->strRmtAuthUsrName.size());
		strncpy(RmtInfo.rmt_auth_pwd, mediaInfo->strRmtAuthPwd.c_str(), mediaInfo->strRmtAuthPwd.size());
		pRmtInfo = &RmtInfo;
	}
	if (pPcapUnit->StartCapture(pRmtInfo, errbuf) == NPCAP_ERROR)
	{
		delete pPcapUnit;
		return NPCAP_ERROR;
	}
	NCGPCAP::g_list_pcapUnits.push_back(pPcapUnit);

	return NPCAP_SUCC;
}
int npcap_pcap_MakeMediaRtspSendPCapUnits(npcap_if_internal* interfaceInfo, npcap_media* mediaInfo, char* errbuf)
{
	if (errbuf == NULL)
	{
		return NPCAP_ERROR;
	}
	CPcapUnit* pPcapUnit = NULL;
	char strFilterTmp[256] = {0};
	npcap_rmt_info *pRmtInfo = NULL, RmtInfo;
	memset(&RmtInfo,0,sizeof(RmtInfo));

	pPcapUnit = new CPcapUnit;
	if (pPcapUnit == NULL)
	{
		_snprintf(errbuf, NPCAP_ERROR_BUFF_SIZE-1, "Allocate space for Capture Unit Failed.");
		return NPCAP_ERROR;
	}

	_snprintf(strFilterTmp, 255, "tcp[0:2] >= %d && tcp[0:2] < %d"
		, mediaInfo->iRtspSendPortBase
		, mediaInfo->iRtspSendPortBase + 2 * mediaInfo->iRtspSendPortNum
		);
	pPcapUnit->SetFilterString(string(strFilterTmp));
	pPcapUnit->SetInterfaceName(interfaceInfo->if_name);
	pPcapUnit->SetNetMask(interfaceInfo->if_netmask);
	pPcapUnit->SetOutputFileName(MakeCaptureOutputFileName(interfaceInfo->if_ip, mediaInfo->iRtspSendPortBase, mediaInfo->iRtspSendPortNum));
	pPcapUnit->SetPacketHandler(pkt_handler_DumpToFile); //This should not be NULL.
	if (mediaInfo->iMediaPosition == NPCAP_MEDIA_REMOTE) 
	{
		strncpy(RmtInfo.rmt_ip,mediaInfo->strRmtIp.c_str(),mediaInfo->strRmtIp.size());
		RmtInfo.rmt_port = mediaInfo->iRmtPort;
		RmtInfo.rmt_auth_mode = int(mediaInfo->iRemoteAuthMode);
		strncpy(RmtInfo.rmt_auth_usrname, mediaInfo->strRmtAuthUsrName.c_str(), mediaInfo->strRmtAuthUsrName.size());
		strncpy(RmtInfo.rmt_auth_pwd, mediaInfo->strRmtAuthPwd.c_str(), mediaInfo->strRmtAuthPwd.size());
		pRmtInfo = &RmtInfo;
	}
	if (pPcapUnit->StartCapture(pRmtInfo, errbuf) == NPCAP_ERROR)
	{
		delete pPcapUnit;
		return NPCAP_ERROR;
	}
	NCGPCAP::g_list_pcapUnits.push_back(pPcapUnit);

	return NPCAP_SUCC;
}

void npcap_pcap_FreeAllPCapUnits()
{
    list<CPcapUnit*>::iterator itCapU = NCGPCAP::g_list_pcapUnits.begin();

    for (; itCapU != NCGPCAP::g_list_pcapUnits.end(); itCapU++)
    {
        (*itCapU)->StopCapture(NULL);
        delete (*itCapU);
        (*itCapU) = NULL;
    }
}

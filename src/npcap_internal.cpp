#include "markup.h"

#include "npcap_internal.h"
#include "npcap_config.h"

using namespace std;

pcap_if_t* NCGPCAP::local_if;

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

int npcap_finddevs_internal(char* source, pcap_rmtauth* rmt_auth,npcap_if_t** alldevices,char* errbuf)
{
	char err_buf[PCAP_BUF_SIZE] = {0};
	if(pcap_findalldevs_ex(source,rmt_auth,&NCGPCAP::local_if,err_buf) == -1)
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

	for (pcap_interface = NCGPCAP::local_if;pcap_interface != NULL; pcap_interface = pcap_interface->next)
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
			CONFIG::npcap_if_internal ifItem;
			ifItem.if_name = cXml.GetData();
			ifItem.if_ip = cXml.GetAttrib("ip");
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
			CONFIG::npcap_media media;
			media.iMediaPosition = CONFIG::NPCAP_MEDIA_LOCAL;

			if (cXml.FindElem("DeviceList",true) == false)
			{
				errElement = "DeviceList";
				break;
			}
			cXml.IntoElem();			//DeviceList
			while (cXml.FindElem("Item"))
			{
				CONFIG::npcap_if_internal ifItem;
				ifItem.if_name = cXml.GetData();
				ifItem.if_ip = cXml.GetAttrib("ip");
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
			CONFIG::npcap_media media;

			media.iMediaPosition = CONFIG::NPCAP_MEDIA_LOCAL;
			
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
			media.iRemoteAuthMode = CONFIG::REMOTE_AUTH_MODE(cXml.GetAttrib("use")=="0"?0:1);
			if (media.iRemoteAuthMode == CONFIG::NPCAP_RMT_AUTH_PWD)
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
				CONFIG::npcap_if_internal ifItem;
				ifItem.if_name = cXml.GetData();
				ifItem.if_ip = cXml.GetAttrib("ip");
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
		_snprintf(errbuf,PCAP_ERRBUF_SIZE-1,"Has not find [%s] element in npcap.conf.xml.",errElement);
	}
	return NPCAP_ERROR;
}

int npcap_pcap_start_internal(char* errbuf)
{
	return NPCAP_SUCC;
}
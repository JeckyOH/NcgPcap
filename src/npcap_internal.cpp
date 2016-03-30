#include "npcap_internal.h"
#include "markup.h"

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

int npcap_pcap_start()
{
	CMarkupSTL cXml();
	
}
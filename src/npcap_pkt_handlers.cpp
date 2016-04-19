#include "npcap_pkt_handlers.h"

void pkt_handler_DumpToFile( void *user
							, void *pDumper
							, const struct pcap_pkthdr *pkt_header
							, const u_char *pkt_data
							)
{
	(void*)user;
	if (pDumper == NULL)
	{
		return;
	}
	pcap_dump((u_char*)pDumper, pkt_header, pkt_data);
}
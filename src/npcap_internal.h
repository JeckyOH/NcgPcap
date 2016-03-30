#ifndef _NPCAP_INTERNAL_H_
#define _NPCAP_INTERNAL_H_

#include "winPcap/pcap.h"
#include "NcgPcap.h"

#define IPTOSBUFFERS	12

struct npcap_rmt_if
{
	char*	rmt_ip;
	unsigned int rmt_port;
	pcap_rmtauth* rmt_auth;
	pcap_if_t* rmt_if;
};

char *iptos(u_long in);

int npcap_finddevs_internal(char* source, pcap_rmtauth* rmt_auth,npcap_if_t** alldevices,char* errbuf);

int npcap_pcap_start();

namespace NCGPCAP{
	extern pcap_if_t* local_if;
}
#endif
#ifndef _NCGPCAP_DEF_H_
#define _NCGPCAP_DEF_H_
#include "winPcap/pcap.h"

struct npcap_rmt_if
{
	char*	rmt_ip;
	unsigned int rmt_port;
	pcap_rmtauth* rmt_auth;
	pcap_if_t* rmt_if;
};

#endif
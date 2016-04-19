
#include "pcap.h"

void pkt_handler_DumpToFile( void *user
							, void *pDumper
							, const struct pcap_pkthdr *pkt_header
							, const u_char *pkt_data
							);
// TestDemos.cpp : 定义控制台应用程序的入口点。
//

#include <iostream>

#include "stdafx.h"
#include "pcap.h"

#include "winsock2.h"

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if(getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}


void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	char ip6str[128];

	/* Name */
	printf("%s\n",d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n",d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

	/* IP addresses */
	for(a=d->addresses;a;a=a->next) {
		printf("\tAddress Family: #%d\n",a->addr->sa_family);

		switch(a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}


/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handlerr(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int _tmain(int argc, _TCHAR* argv[])
{
	pcap_if_t* allDev;
	pcap_if_t* curDev;

	char errbuf[PCAP_ERRBUF_SIZE+1];
	char source[PCAP_BUF_SIZE+1];

	int select = 0;

	printf("Enter the device you want to list:\n");

	//fgets(source, PCAP_ERRBUF_SIZE, stdin);
	//source[PCAP_ERRBUF_SIZE] = '\0';

	memset(source,0,PCAP_ERRBUF_SIZE+1);
	pcap_createsrcstr(source,PCAP_SRC_IFREMOTE,"10.20.147.40","2002",NULL,errbuf);

	pcap_rmtauth auth;
	auth.type = RPCAP_RMTAUTH_PWD;
	auth.username = "administrator";
	auth.password = "hik12345+";

	if (pcap_findalldevs_ex(source, &auth, &allDev, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
		system("pause");
		exit(1);
	}

	/* Scan the list printing every entry */
	for(curDev=allDev;curDev;curDev=curDev->next)
	{
		ifprint(curDev);
	}

	printf("Enter selection:\n");
	std::cin >> select;
	int i = 0;
	for (i = 1,curDev = allDev;curDev&&i<select;curDev=curDev->next,i++);

	pcap_t* pcap_handle;

	if ((pcap_handle = pcap_open(curDev->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,&auth,errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(allDev);
		return -1;
	}

	pcap_loop(pcap_handle,0,packet_handlerr,NULL);
	pcap_freealldevs(allDev);

	system("pause");
	return 0;
}

void packet_handlerr(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * Unused variable
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}

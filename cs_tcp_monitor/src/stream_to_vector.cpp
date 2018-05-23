/*
 * stream_to_vector.cpp
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#include "stream_to_vector.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap.h>
#include "debug.h"
#define KNOW_INTRANET 1
#define KNOW_EXTRANET 0
unsigned int subnet_intranet = ntohl(inet_addr("61.161.0.0"));      //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_extranet = ntohl(inet_addr("108.0.0.0"));     //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_mask = ntohl(inet_addr("255.255.0.0"));  //设定子网掩码，用于区获取子网号

flow_vector stream_to_vector(char*dir){
	flow_vector cur_flow;
	cur_flow.init();
	cur_flow.name = std::string(dir);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    char tcpbuf[1<<12];
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL){
    	printf("pcap_open_offline(): %s\n", errbuf);
    	printf("%s\n", dir);
    	pcap_close(descr);
    	return cur_flow;
    }
    int cnt=0;
	struct in_addr srcip, dstip;
	std::string sip, dip, name;
  	bool tag;
    while(true){

    	packet = pcap_next(descr, &hdr);
    	if(packet == NULL){
//    		printf("Finish reading!\n");
    		break;
    	}
        ipptr = (struct iphdr*)(packet + sizeof(ether_header));
    	tcpptr = (struct tcphdr*)(packet + sizeof(ether_header) + (ipptr->ihl)*4);
    	memset(tcpbuf,0,sizeof(tcpbuf));
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	sip = inet_ntoa(srcip);
    	dip = inet_ntoa(dstip);
    	tag = 0;
    	int tcplen = ipptr->tot_len - ipptr->ihl*4 - tcpptr->th_off*4;
    	if(tcplen < 1 ) continue;
//    	printf("sip: %u dip: %u subnet_mask:%u subnet_intranet:%u \n", ntohl(ipptr->saddr), ntohl(ipptr->daddr), subnet_mask, subnet_intranet);
#if(KNOW_INTRANET)
    	if( (ntohl(ipptr->saddr) & subnet_mask) == subnet_intranet &&\
    	    (ntohl(ipptr->daddr) & subnet_mask) == subnet_intranet)
    		continue;
    	else if((ntohl(ipptr->saddr) & subnet_mask) != subnet_intranet &&\
    			(ntohl(ipptr->daddr) & subnet_mask) != subnet_intranet)
    		continue;
    	else if((ntohl(ipptr->saddr) & subnet_mask) == subnet_intranet) tag = 1;
    	else{
    		tag = 0;
    		swap(sip, dip);
    	}
#elif(KNOW_EXTRANET)
    	if( (ntohl(ipptr->saddr) & subnet_mask) == subnet_extranet &&\
    	    (ntohl(ipptr->daddr) & subnet_mask) == subnet_extranet)
    		continue;
    	else if((ntohl(ipptr->saddr) & subnet_mask) != subnet_extranet &&\
    			(ntohl(ipptr->daddr) & subnet_mask) != subnet_extranet)
    		continue;
    	else if((ntohl(ipptr->saddr) & subnet_mask) != subnet_extranet) tag = 1;
    	else{
    		tag = 0;
    		swap(sip, dip);
    	}
#endif
    	cur_flow.pkt_sign[cnt] = tcpptr->fin|((tcpptr->syn)<<1)|(tcpptr->psh<<3)|(tcpptr->rst<<2);
    	cur_flow.pkt_size[cnt] = hdr.caplen;
    	cur_flow.pkt_tag[cnt] = tag;

    	cur_flow.pkt_time[cnt] = double(hdr.ts.tv_sec) + double(hdr.ts.tv_usec/1000000.0);
    	cnt++;
    }
	cur_flow.pkt_num=cnt;
    pcap_close(descr);
    return cur_flow;
}




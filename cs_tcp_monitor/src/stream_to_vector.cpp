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
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <map>
#include <pcap.h>
#include "debug.h"
#include "init.h"
#define KNOW_INTRANET 1
#define KNOW_EXTRANET 0
#define HOLE_SIZE 600
unsigned int subnet_intranet = ntohl(inet_addr("61.161.0.0"));      //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_extranet = ntohl(inet_addr("108.0.0.0"));     //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_mask = ntohl(inet_addr("255.255.0.0"));  //设定子网掩码，用于区获取子网号

//std::map<std::string, int> dns_show;
//std::map<std::pair<std::string,std::string>, int> hostnum;
//std::map<std::string, int> white_list;

dns_vector dns_stream_to_vector(char*dir){
	int host_name_num[HOLE_SIZE];
	bool domain[HOLE_SIZE][HOLE_SIZE];
	memset(host_name_num,0,sizeof(host_name_num));
	memset(domain,0,sizeof(domain));
	dns_show.clear();
	hostnum.clear();
	dns_vector cur_flow;
	cur_flow.init();
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct iphdr *ipptr;
	struct udphdr *udpptr;
	struct dnshdr *dnsptr;
	char dnsbuf[1<<12];
	descr = pcap_open_offline(dir,errbuf);
	if(descr == NULL){
		printf("pcap_open_offline(): %s\n", errbuf);
		printf("%s\n", dir);
		pcap_close(descr);
		return cur_flow;
	}
	int cnt = 0;
	struct in_addr srcip, dstip;
	std::string sip, dip, name;
	bool tag;
	while(true){
	//	printf("%d\n", cnt);
		packet = pcap_next(descr, &hdr);
		if(packet == NULL){
//			printf("FINISH READING\n");
			break;
		}
		ipptr = (struct iphdr*)(packet + sizeof(ether_header));
		udpptr = (struct udphdr*)(packet + sizeof(ether_header) + (ipptr->ihl)*4);
		dnsptr = (struct dnshdr*)(packet + sizeof(ether_header) + (ipptr->ihl)*4 + 8);
		memset(dnsbuf, 0, sizeof(dnsbuf));
		srcip.s_addr = in_addr_t(ipptr->saddr);
		dstip.s_addr = in_addr_t(ipptr->daddr);
		uint16_t sport = ntohs(udpptr->source);
		uint16_t dport = ntohs(udpptr->dest);
		sip = inet_ntoa(srcip);
		dip = inet_ntoa(dstip);
		tag = 0;
		int dnslen = ntohs(udpptr->len) - 8;
		if(dnslen < 1) continue;
		if(dport==uint16_t(53)) {cur_flow.upload_num++;cur_flow.upload+=dnslen;}
		else {cur_flow.download_num++;cur_flow.download+=dnslen;}

		//if a packet is too small , do not
		if(dnslen<10) continue;
		cnt++;
		memcpy(dnsbuf, (packet + sizeof(ether_header) + (ipptr->ihl)*4 + 8 + 12), dnslen);
		if((ntohs(dnsptr->qsnum) > u_int16_t(5)) || (ntohs(dnsptr->anrnum) > u_int16_t(100)) || (ntohs(dnsptr->aurnum) > u_int16_t(100)) || (ntohs(dnsptr->adrnum)>u_int16_t(100))){
			cur_flow.pkt[cnt].malformed = true;
			cur_flow.malformed_num++;
			continue;
		}
		else cur_flow.pkt[cnt].malformed = false;
		if( dnslen != ntohs(udpptr->len)-8){
			cur_flow.pkt[cnt].malformed = true;
			cur_flow.malformed_num++;
			continue;
		}
		for(int i=0;i<ntohs(dnsptr->qsnum);i++){
			int pos = 0;
			int cnt = 0;
			std::string domain = "";
			while(dnsbuf[pos]!='\x00'){
				cnt = int(dnsbuf[pos]);
				for(int i=1;i<=cnt;i++)
					domain += dnsbuf[++pos];
				pos++;
				if(dnsbuf[pos]=='\x00')break;
				domain += '.';
			}
			int dotpos;
			int dotnum = 0;
			int secdotpos;
			for(int j = domain.length()-1;j>=0;j--)
				if(domain[j]=='.'){
					dotnum++;
					if(dotnum==2)
						secdotpos=j;
				}
			if(dotnum==1){
				if(dns_show.count(domain)) continue;
				else{
					cur_flow.domain_num++;
					dns_show[domain]=1;
				}
			}
			else if(dotnum>1){
				std::string topdomain = domain.substr(secdotpos+1);
				std::string hostname = domain.substr(0,secdotpos);
				std::pair<std::string,std::string> cur_pair = make_pair(topdomain,hostname);
				//std::cout<<"topdomain is "<<topdomain<<" hostname is "<<hostname<<std::endl;
				//printf("topdomain is %s  hostname is %s\n", topdomain, hostname);
				if(hostnum.count(cur_pair)) continue;
				else {
					hostnum[cur_pair] = 1;
					dns_show[topdomain]++;
				}
				if(white_list.count(topdomain)){
					if(dport==uint16_t(53)) {cur_flow.upload_num--;cur_flow.upload-=dnslen;}
					else {cur_flow.download_num--;cur_flow.download-=dnslen;}
				}
			}
		}
	}
	cur_flow.max_host_name_num = -1;
	for(std::map<std::string, int>::iterator i=dns_show.begin();i!=dns_show.end();i++)
		cur_flow.max_host_name_num = std::max(cur_flow.max_host_name_num, i->second);
	return cur_flow;
}


tcp_vector tcp_stream_to_vector(char*dir){
	tcp_vector cur_flow;
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




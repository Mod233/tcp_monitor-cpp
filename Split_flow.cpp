#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <vector>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <thread>
#include <netinet/udp.h>
#define SHOW_CHILD_PATH 1

std::map<std::string,int> show;
#define DEBUG 1
#define BUFSIZE 1<<10
void cmd_run(std::string cmd){
	char cli_output[BUFSIZE];
	FILE *fp;
	memset(cli_output,0,sizeof(cli_output));
	const char* sysCommand = cmd.data();
	if((fp = popen(sysCommand, "r")) == NULL){
		printf("%s command error\n", sysCommand);
		return;
	}
	while(fgets(cli_output, sizeof(cli_output)-1, fp)!=NULL)
		printf("%s", cli_output);
	pclose(fp);
}

void highlight_output(int color_id, char*msg){
	printf("\033[1;%dm%s\033[1;0m\n", color_id, msg);
}

int dns_ip(char*dir, std::string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct udphdr *udpptr;
    descr = pcap_open_offline(dir, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        pcap_close(descr);
        return 0;
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr, &hdr);
    	if(packet == NULL)
    		break;
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type) != 0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip, dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 17) continue;
    	udpptr = (struct udphdr *)(packet+sizeof(ether_header)+(ipptr->ihl)*4);
    	uint16_t sport = ntohs(udpptr->source);
    	uint16_t dport = ntohs(udpptr->dest);
    	std::string sip=inet_ntoa(srcip);
    	std::string dip=inet_ntoa(dstip);
    	if(dport != uint16_t(53) && sport != uint16_t(53)) continue;
    	std::string name;
    	if(dport == uint16_t(53)) name = dip+"-"+sip; //+":"+to_string(sport);
    	else name = sip + "-" + dip; //+":"+to_string(dport);
    	name = result + "/dns/" + name + std::string(".pcap");
    	FILE* pFile;
    	if(show.count(name)){
    		show[name]++;
    		pFile = fopen(name.c_str(),"a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		show[name] = 1;
    		pcap_file_header ph;
    		ph.magic = 0xa1b2c3d4;
    		ph.version_major = 0x02;
    		ph.version_minor = 0x04;
    		ph.thiszone = 0;
    		ph.sigfigs = 0;
    		ph.snaplen = 65535;
    		ph.linktype = 0x1;
    		pFile = fopen(name.c_str(), "w");
    		fwrite(&ph, 1, 24, pFile);
    		fwrite(&hdr.ts.tv_sec, 1, 4, pFile);
    		fwrite(&hdr.ts.tv_usec, 1, 4, pFile);
    		fwrite(&hdr.caplen, 1, 8, pFile);
    		fwrite(packet, 1, hdr.caplen, pFile);
    		fclose(pFile);
    	}
    }
    pcap_close(descr);
    return 0;
}

int tcp_ip(char*dir, std::string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        pcap_close(descr);
        return 0;
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr,&hdr);
    	if(packet == NULL)
    		break;
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip,dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 6) continue;
    	tcpptr = (struct tcphdr *)(packet+sizeof(ether_header)+(ipptr->ihl)*4);
    	uint16_t sport = ntohs(tcpptr->source);
    	uint16_t dport = ntohs(tcpptr->dest);
    	if(dport == uint16_t(53) || sport == uint16_t(53) || dport == uint16_t(443) || sport == uint16_t(443)) continue;
    	std::string sip=inet_ntoa(srcip);
    	std::string dip=inet_ntoa(dstip);
    	std::string name;
    	name = min(sip, dip) + '-' + max(sip, dip);
    	name = result + "/tcp/" + name + std::string(".pcap");
    	FILE* pFile;
    	if(show.count(name)){
    		show[name]++;
    		pFile=fopen(name.c_str(),"a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		show[name]=1;
    		pcap_file_header ph;
    		ph.magic=0xa1b2c3d4;
    		ph.version_major=0x02;
    		ph.version_minor=0x04;
    		ph.thiszone=0;
    		ph.sigfigs=0;
    		ph.snaplen=65535;
    		ph.linktype=0x1;
    		pFile=fopen(name.c_str(),"w");
    		fwrite(&ph,1,24,pFile);
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    }
    pcap_close(descr);
    return 0;
}

int https_noack(char*dir, std::string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL){
        printf("pcap_open_offlive(): %s\n",errbuf);
        pcap_close(descr);
        return 0;
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr,&hdr);
    	if(packet == NULL) break;
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip,dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 6) continue;
    	if(ntohs(ipptr->tot_len) < 42) continue;
    	tcpptr = (struct tcphdr *)(packet+sizeof(ether_header)+(ipptr->ihl)*4);
    	uint16_t dport = ntohs(tcpptr->dest);
    	uint16_t sport = ntohs(tcpptr->source);
    //	if( dport != uint16_t(80) && sport != uint16_t(80)) continue;
    	if(hdr.caplen-(sizeof(ether_header)+(ipptr->ihl)*4+(tcpptr->th_off)*4)==0) continue;


    	if(ipptr->ttl-(ipptr->ihl)*4-(tcpptr->th_off)*4>0)
    		if(packet[sizeof(ether_header)+(ipptr->ihl)*4+(tcpptr->th_off)*4]!='\x17') continue;

    	std::string sip=inet_ntoa(srcip);
    	std::string dip=inet_ntoa(dstip);
    	std::string name;
    	name = min(sip, dip) + '-' + max(sip, dip);
    	FILE* pFile;
    	if(show.count(name))
    		show[name]++;
    	else show[name]=0;
    	std::string filedir = result + "/https_noack/" + name;
    	int flag = mkdir(filedir.c_str(), 0777);
   // 	if(flag!=0) printf("mkdir file %s failed\n", filedir.c_str());
    	if(show[name]%300!=0){
    		char filename[100];
    		sprintf(filename, "%s/%s-%s-%d.pcap", filedir.c_str(), min(sip, dip).c_str(), max(sip, dip).c_str(), show[name]/300);
    		pFile=fopen(filename, "a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		pcap_file_header ph;
    		ph.magic=0xa1b2c3d4;
    		ph.version_major=0x02;
    		ph.version_minor=0x04;
    		ph.thiszone=0;
    		ph.sigfigs=0;
    		ph.snaplen=65535;
    		ph.linktype=0x1;
    		char filename[100];
    		sprintf(filename, "%s/%s-%s-%d.pcap", filedir.c_str(), min(sip, dip).c_str(), max(sip, dip).c_str(), show[name]/300);
    		pFile=fopen(filename, "w");
    		fwrite(&ph,1,24,pFile);
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    }
    pcap_close(descr);
    return 0;
}


int read_file(char* base_dir){
	DIR* pdir;
	struct dirent *ent;
	char childpath[512];
	pdir = opendir(base_dir);
	highlight_output(32, "#######################     Dectecting  Begin     ########################\n");
	printf("\n");
	highlight_output(33, "#######################  Proproccessing PcapFile  ########################\n");
	memset(childpath,0,sizeof(childpath));
	while((ent = readdir(pdir))!=NULL){
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if(ent->d_type & DT_DIR){
			if((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) continue;
			read_file(childpath);
		}
		else{
#if(SHOW_CHILD_PATH)
			std::string msg = "Proproccessing " + std::string(childpath);
			highlight_output(34, (char*)msg.c_str());
			//printf("childpath is %s\n", childpath);
#endif
		    std::string result = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow";
		    dns_ip(childpath, result);
		    tcp_ip(childpath, result);
		    https_noack(childpath, result);
		    //printf("Finish reading %s\n\n", childpath);
		    //pair_ip(childpath, result);
		}
	}
	highlight_output(33, "#######################  Finished Proproccessing  ########################\n");
	closedir(pdir);
	return 0;
}



int main(int argc, char **argv){
#if(!DEBUG)
    char dir[200];
    string result;
    printf("Input original flow dir\n");
    scanf("%s", dir);
    if(strlen(dir)>200 || strlen(dir)<0 ){
        printf("dir is too long!\n");
        return 0;
    }
    char dir2[50];
    printf("Input result flow dir\n");
    scanf("%s", dir2);
    if(strlen(dir2)>200 || strlen(dir2)<0){
        printf("result flow dir is too long\n");
        return 0;
    }
    result=string(dir2);
#else
//    char dir[200] = "/mnt/myusbmount/Trojan_Monitor/luoyang/jindun1.pcap";
//    std::string result = "/mnt/myusbmount/Trojan_Monitor/IP_FLOW";
#endif
    char dir[200] = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/PcapFile";
    //cmd_run("./https.out 1.1.1.1");
    //cmd_run("python cs_dns_ip_pair.py");
    read_file(dir);
    highlight_output(34, "#######################    Dectecting  Trojan     ########################\n");
    //std::thread th1(cmd_run, "python cs_dns_ip_pair.py");
    std::thread th2(cmd_run, "./https.out");
    //std::thread th3(cmd_run, "./tcp.out 108.0.0.0");
    //th1.join();
    th2.join();
    //th3.join();
    highlight_output(34, "#######################    Finish  Dectecting     ########################\n");

//    dns_ip(dir, result);
//    tcp_ip(dir, result);
//    pair_ip(dir, result);
    highlight_output(33, "#######################         Finish  All       ########################\n");
    return 0;
}





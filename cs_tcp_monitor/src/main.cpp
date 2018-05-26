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
#include <set>
#include <cmath>
#include <vector>
#include <netinet/udp.h>
#include "stream_to_vector.h"
#include "judge_out_control.h"
#ifdef linux
#include <unistd.h>
#include <dirent.h>
#include "debug.h"
#elif WIN32
#include <direct.h>
#endif


char dir_https[] = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/https_noack";
char dir_dns[] = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/dns";
void highlight_output(int color_id, char*msg){
	//"RED": 31, "GREEN": 32, "YELLOW": 33, "BLUE": 34, "PURPLE": 35, "CYAN": 36, "GREY": 37, "WHITE": 38
	printf("\033[1;%dm%s\033[1;0m\n", color_id, msg);
}

int dns_read_file(char* base_dir){
	DIR* pdir;
	struct dirent * ent;
	char childpath[512];
	pdir = opendir(base_dir);
	memset(childpath, 0, sizeof(childpath));
	while((ent = readdir(pdir)) != NULL){
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if(ent->d_type & DT_DIR){
			if((strcmp(ent->d_name, ".")==0) || (strcmp(ent->d_name, ".."))==0) continue;
			dns_read_file(childpath);
		}
		else{
#if(SHOW_CHILD_PATH)
			printf("childpath is %s\n", childpath);
#endif
			dns_vector cur = dns_stream_to_vector(childpath);
			int ret = judge_dns(cur);
			if(ret){
				int pos;
				for(pos = strlen(childpath)-1;pos>=0;pos--) if(childpath[pos]=='/') break;
				std::string filename = std::string(childpath+pos+1);
				std::string warning;
				if(ret==1) warning= "dns-malformed - " + filename;
				else warning = "dns-max_host_name - " + filename;
				//printf("https-dangerous - %s\n", filename.c_str());
				highlight_output(31, (char*)warning.c_str());
				filename = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/Warning/dns_warning/"+ filename;
				std::string cmd = "cp " + std::string(childpath) + std::string(" ") + filename;
				system(cmd.c_str());
			}
		}
	}
	return 0;
}


int tcp_read_file(char* base_dir){
	DIR* pdir;
	struct dirent *ent;
	char childpath[512];
	pdir = opendir(base_dir);
	memset(childpath,0,sizeof(childpath));
	while((ent = readdir(pdir))!=NULL){
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if(ent->d_type & DT_DIR){
			if((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) continue;
			tcp_read_file(childpath);
		}
		else{
#if(SHOW_CHILD_PATH)
			printf("childpath is %s\n", childpath);
#endif
			tcp_vector cur = tcp_stream_to_vector(childpath);
			int ret = judge_tcp(cur);

			if(ret){
				int pos;
				for(pos = strlen(childpath)-1;pos>=0;pos--) if(childpath[pos]=='/') break;
				std::string filename = std::string(childpath + pos + 1);
				std::string warning = "https-dangerous - " + filename;
				//printf("https-dangerous - %s\n", filename.c_str());
				highlight_output(31, (char*)warning.c_str());
				filename = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/Warning/https_warning/"+ filename;
				std::string cmd = "cp " + std::string(childpath) + std::string(" ") + filename;
				system(cmd.c_str());
			}
				//printf("######################\n%s is dangerous\n######################\n", childpath);
		}
	}
	//closedir(pdir);
	return 0;
}


int main(int argc,const char*argv[]) {
//	printf("Begining!\n");
#if(JUDGE_FILE)
	tcp_read_file(dir_https);
	dns_read_file(dir_dns);

#else
	flow_vector cur =stream_to_vector(dir);
	int ret = judge_tcp(cur);
	if(ret)
		printf("%s is dangerous\n", dir);
#endif
//	printf("Finish!\n");
	printf("\n\n");
	return 0;
}

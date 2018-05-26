/*
 * stream_to_vector.h
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#ifndef STREAM_TO_VECTOR_H_
#define STREAM_TO_VECTOR_H_
#include <cstring>
#include <sys/types.h>
#include <string>
#define PKT_NUM 320

struct dns_packet{
	bool malformed;

};

struct dns_vector{
	int port;
	int domain_num;
	double time;
	std::string name;
	long long upload;
	int upload_num;
	long long download;
	int download_num;
	int malformed_num;
	int transaction_num;
	int max_host_name_num;
	dns_packet pkt[300];
	dns_vector(){
		port = 0;
		domain_num = 0;
		time = 0.0;
		upload = 0;
		upload_num = 0;
		download = 0;
		download_num = 0;
		malformed_num = 0;
		transaction_num = 0;
		max_host_name_num = 0;
	}
	void init(){
		port = 0;
		domain_num = 0;
		time = 0.0;
		upload = 0;
		upload_num = 0;
		download = 0;
		download_num = 0;
		malformed_num = 0;
		transaction_num = 0;
		max_host_name_num = 0;
	}
};

struct dnshdr{
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qsnum;
	u_int16_t anrnum;
	u_int16_t aurnum;
	u_int16_t adrnum;
};

struct tcp_vector{
	std::string name;
	double pkt_time[PKT_NUM];
	unsigned int pkt_size[PKT_NUM];
	unsigned short pkt_sign[PKT_NUM];
	bool pkt_tag[PKT_NUM];
	int pkt_num;
	tcp_vector(){
		pkt_num=0;
		memset(pkt_time,0,sizeof(pkt_time));
		memset(pkt_sign,0,sizeof(pkt_sign));
		memset(pkt_tag,0,sizeof(pkt_tag));
	}
	void init(){
		pkt_num=0;
		memset(pkt_time,0,sizeof(pkt_time));
		memset(pkt_sign,0,sizeof(pkt_sign));
		memset(pkt_tag,0,sizeof(pkt_tag));
	}
};

struct cluster_vector{
	int pkt_num;
	double pkt_time[PKT_NUM];
	unsigned int pkt_size[PKT_NUM];
	bool pkt_tag[PKT_NUM];
	cluster_vector(){
		pkt_num = 0;
		memset(pkt_time,0,sizeof(pkt_time));
		memset(pkt_size,0,sizeof(pkt_size));
		memset(pkt_tag,0,sizeof(pkt_tag));
	}
	void init(){
		pkt_num = 0;
		memset(pkt_time,0,sizeof(pkt_time));
		memset(pkt_size,0,sizeof(pkt_size));
		memset(pkt_tag,0,sizeof(pkt_tag));
	}
	bool operator<(cluster_vector const& rhs) {
		if(pkt_num == rhs.pkt_num)
			if(!memcpy(pkt_time,rhs.pkt_time,PKT_NUM))
				return memcpy(pkt_tag,rhs.pkt_tag,PKT_NUM);
			else return memcpy(pkt_time,rhs.pkt_time,PKT_NUM);
		else return pkt_num<rhs.pkt_num;
	}
};

struct tid_vector{
	int tid_size;
	int tid_item[PKT_NUM][4];
	tid_vector(){
		tid_size = 0;
		memset(tid_item,0,sizeof(tid_item));
	}
	void init(){
		tid_size = 0;
		memset(tid_item,0,sizeof(tid_item));
	}
};

tcp_vector tcp_stream_to_vector(char*dir);

dns_vector dns_stream_to_vector(char*dir);

#endif /* STREAM_TO_VECTOR_H_ */

/*
 * stream_to_vector.h
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#ifndef STREAM_TO_VECTOR_H_
#define STREAM_TO_VECTOR_H_
#include <cstring>
#include <string>
#define PKT_NUM 320


class flow_vector{
public:
	std::string name;
	double pkt_time[PKT_NUM];
	unsigned int pkt_size[PKT_NUM];
	unsigned short pkt_sign[PKT_NUM];
	bool pkt_tag[PKT_NUM];
	int pkt_num;
	flow_vector(){
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

class cluster_vector{
public:
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

class tid_vector{
public:
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

flow_vector stream_to_vector(char*dir);

#endif /* STREAM_TO_VECTOR_H_ */

/*
 * judge.cpp
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */
#include "stream_to_vector.h"
#include "apriori_cut_heartbeat.h"
#include <cstdio>
#include <string>
#include <map>
#include "debug.h"
#define CLU_NUM 70
#define SLICE_NUM 50
int time_slice(flow_vector stream_vector, double delta_time, cluster_vector* clu){
	int pos = 0;
	int n = 0;
	for(int i=0;i<CLU_NUM;i++)
		clu[i].init();
	for(int i=1;i<PKT_NUM;i++){
		if((stream_vector.pkt_time[i]-stream_vector.pkt_time[i-1]>0.8) && (stream_vector.pkt_time[i]-stream_vector.pkt_time[i-1]> 5 || stream_vector.pkt_time[i] - stream_vector.pkt_time[pos] > delta_time || ((i-pos)>1 && (stream_vector.pkt_time[i] - stream_vector.pkt_time[i-1])*(i-1-pos) > 10*(stream_vector.pkt_time[i]-stream_vector.pkt_time[pos])))){
			clu[n].pkt_num = i - pos;
			for(int j=pos;j<i;j++){
				if(stream_vector.pkt_size[j] < 2 ) break;
				clu[n].pkt_time[j-pos] = stream_vector.pkt_time[j];
				clu[n].pkt_tag[j-pos] = stream_vector.pkt_tag[j];
				clu[n].pkt_size[j-pos] = stream_vector.pkt_size[j];
			}
			pos = i;
			n++;
			if(n == SLICE_NUM)
				break;
		}
	}
	if(n < SLICE_NUM){
		clu[n].pkt_num = 0;
		for(int j=pos;j<PKT_NUM;j++){
			if(stream_vector.pkt_size[j] < 2  ) break;
//			if(n==47) printf("%d size is %u\n", j, stream_vector.pkt_size[j]);
			clu[n].pkt_time[j-pos] = stream_vector.pkt_time[j];
			clu[n].pkt_tag[j-pos] = stream_vector.pkt_tag[j];
			clu[n].pkt_size[j-pos] = stream_vector.pkt_size[j];
			clu[n].pkt_num++;
		}
		n++;
	}
	return n;
}


int judge_out_control(flow_vector stream_vector, cluster_vector* clu){
	if(stream_vector.pkt_num<300) return 0;
	int slice_num = 0;
	int heart_num;
	char packet_sign_list[PKT_NUM];
	int packet_signed_size_list[PKT_NUM];
	double packet_arrival_time_list[PKT_NUM];
	double delta_arrival_time;
	double arrival_time_max=0.0;

	for(int i=1;i<PKT_NUM;i++){
		delta_arrival_time = stream_vector.pkt_time[i] - stream_vector.pkt_time[i-1];
		arrival_time_max = std::max(arrival_time_max, delta_arrival_time);
	}
	slice_num = time_slice(stream_vector, arrival_time_max/2.0, clu);
	double delta_time_first = 0.0;
	delta_time_first = clu[1].pkt_time[0] - clu[0].pkt_time[0];
//	if(delta_time_first < 0.95) return 0;


#if(SHOW_SLICE_RESULT)
	printf("slice num is %d\n", slice_num);
	for(int i=0;i<slice_num;i++){
		printf("slice_num %d:\n", i);
		for(int j=0;j<clu[i].pkt_num;j++){
			if(clu[i].pkt_tag[j]) printf("%u ", clu[i].pkt_size[j]);
			else printf("-%u ", clu[i].pkt_size[j]);
		}
		printf("\n");
	}
#endif
	if(slice_num < 3){
#if(SHOW_SLICE_RESULT)
		printf("not enough slice_num\n");
#endif
		return 0;
	}
	int outctl_num = 0;
	int single_pkt_num = 0;
	// clu集是没有去心跳的，下面依据 heart 数组去心跳。
	int heart[10];
	memset(heart,0,sizeof(heart));
	#if(CUT_HEARTBEAT)
	heart_num = find_heartbeat(slice_num, clu, CONFIGDENT, heart);
	int heart[10];
	memset(heart,0,sizeof(heart));
	heart_num = find_heartbeat(slice_num, clu, CONFIGDENT, heart);
	bool vis[10];
	for(int i=0;i<slice_num;i++){
		memset(vis,0,sizeof(vis));
		for(int j=0;j<clu[i].pkt_num;j++){
			int tmp = clu[i].pkt_tag[j]?clu[i].pkt_size[j]:-clu[i].pkt_size[j];
			for(int k=0;k<heart_num;k++){
				if(vis[k]) continue;          //心跳只去一次
				if(heart[k] == tmp){
					vis[k] = 1;
					clu[i].pkt_tag[j] = 0;
					clu[i].pkt_size[j] = 0;
					clu[i].pkt_num--;
					break;
				}
			}
		}
	}
#endif
#if(SHOW_SLICE_RESULT_AFTER_CUT)
	printf("heartbeat is \n");
	for(int i=0;i<heart_num;i++)
		printf("%d ", heart[i]);
	printf("\n");
	printf("\n\n$$$$$$after heartbeat cut$$$$$$\n\n");
	printf("slice num is %d\n", slice_num);
	for(int i=0;i<slice_num;i++){
		printf("slice_num %d:\n", i);
		int pos = 0;
		for(int j=0;j<clu[i].pkt_num;j++){
			while(clu[i].pkt_size[pos]<2) pos++;
			if(clu[i].pkt_tag[pos]) printf("%u ", clu[i].pkt_size[pos]);
			else printf("-%u ", clu[i].pkt_size[pos]);
			pos++;
		}
		printf("\n");
	}
#endif

	//if(clu[0].pkt_num<300) return 0;
	for(int i=0;i<slice_num;i++){

		if(clu[i].pkt_num == 1) {single_pkt_num++;continue;}
		int pos=0,pos2,pos3;
		while(clu[i].pkt_size[pos]<1) pos++;
		if(clu[i].pkt_tag[pos]) continue;
		pos2 = pos+1;
		while(clu[i].pkt_size[pos2]<1) pos2++;
		//printf("clu %d size is %d\n",i,clu[i].pkt_num);
		//printf("pos is %d pos2 is %d\n", pos, pos2);
		if(clu[i].pkt_num > 3){
			pos3 = pos2 + 1;
			while(clu[i].pkt_size[pos3]<1) pos3++;
			if(clu[i].pkt_tag[pos2] || clu[i].pkt_tag[pos3]){
				outctl_num++;
				//printf("slice num is %d pkt_num is %d\n", i,clu[i].pkt_num);
			}
		}
		else if(clu[i].pkt_num >1){
			if(clu[i].pkt_tag[pos2]){
				outctl_num++;
				//printf("slice num is %d pkt_num is %d\n", i,clu[i].pkt_num);
			}
		}
	}
#if(SHOW_OUTCTL)
	printf("outctl_num is %d ~~~~ slice_num is %d\n", outctl_num, slice_num - single_pkt_num);
#endif
	//beijing add
	if(slice_num<5) return 0;
	if(outctl_num > (slice_num - single_pkt_num)/4) return 1;
	else return 0;
}


// 对攻击进行判断
int judge_tcp(flow_vector stream_vector){
	cluster_vector clu[CLU_NUM];
	int outnet_ctl = 0;
	unsigned int up_num = 0;
	unsigned int up_syn_num = 0;
	unsigned int down_num = 0;
	unsigned int down_syn_num = 0;
	float up_syn_ratio = 0.0;
	float down_syn_ratio = 0.0;
	unsigned int up_num_no_ack = 0;
	int synackfromin = 0;
	for(int i=0;i<PKT_NUM;i++){
		if(stream_vector.pkt_tag[i]){
			up_num ++ ;
			if(stream_vector.pkt_sign[i] & 2)
				up_syn_num ++;
		}
		else{
			down_num ++;
			if(stream_vector.pkt_sign[i] & 2)
				down_syn_num ++;
		}
	}
	up_syn_ratio = up_num >2 ? up_syn_num*1.0/(up_num*1.0):0.0;
	down_syn_ratio = down_num >2 ? down_syn_num*1.0/(down_num*1.0):0.0;
	outnet_ctl = judge_out_control(stream_vector,clu);
	return outnet_ctl;
}

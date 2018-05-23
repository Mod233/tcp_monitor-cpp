/*
 * apriori.cpp
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#include <iostream>
#include <set>
#include <map>
#include <cstdio>
#include <string>
#include "stream_to_vector.h"
#include <vector>
#include <cstdlib>
#include "debug.h"
typedef std::map<std::set<std::string>,int> map_s;


int compset(std::set<std::string> s1,std::set<std::string> s2){
	int flag=0;
  //判断集合s1是不是s2的子集
	for(std::set<std::string>::iterator it=s1.begin(); it!=s1.end();it++ ){//s1有元素不在s2中
		if(s2.find(*it)==s2.end()){
			flag=10;
			break;
		}
	}
	for(std::set<std::string>::iterator it=s2.begin(); it!=s2.end();it++){//s2有元素不在s1中
		if(s1.find(*it)==s1.end()){
			flag+=1;
			break;
		}
	}
  /*当flag==0,s1元素全部在s2中，s2元素也全部在s1中，s1==s2
    当flag==10,s1有元素不在s2中，s2所有元素都在s1中，s1包含了s2
    当flag==1,s1所有元素在s2中，s2有元素不在s1中，s2包含了s1
    当flag==11,s1 s2集合互不包含
  */
	return flag;
}

map_s apriori_gen(map_s Ck,int k,std::vector<std::set<std::string> > data,  std::vector<std::set<std::string> >  L,int minSup){
   //生成子集
   map_s Ck_temp;
   std::set<std::string> s_temp;

   for(map_s::iterator l_it1=Ck.begin();l_it1!=Ck.end();l_it1++ ){
      for(map_s::iterator l_it2=Ck.begin();l_it2!=Ck.end();l_it2++ ){
         //如果两个set一样，则说明是同一个KEY，跳过
         if(!((l_it1->first > l_it2->first)||(l_it1->first < l_it2->first))) continue;
         //否则开始组装,遍历整个Ck
         for(std::set<std::string>::iterator s_it=l_it2->first.begin();s_it!=l_it2->first.end();s_it++){
               //如果该值在l_it1 set里面可以找到，不能组装
               if(l_it1->first.find(*s_it)!=l_it1->first.end())
                  continue;
               //否则进行组装,先把l_it1的set复制进去
               s_temp = l_it1->first;
               //再把l_it2的值放进去
               s_temp.insert(*s_it);
               //判断该组装的set是否已在生成集合中，如果之前已生成，则不需要往下运算
               if(Ck_temp.find(s_temp)!=Ck_temp.end()) continue;
               else  //否则放到生成的子集中
            	   Ck_temp.insert(std::pair<std::set<std::string>,int >(s_temp,0));
         }
      }
   }

   //对于k=2的情况，需要扫描原始数据得出计数值
	if(k == 2){
		for(map_s::iterator l_it=Ck_temp.begin();l_it!=Ck_temp.end();l_it++ )
			for(int i=0;i<data.size();i++) //l_it集合被data[i]完整包含，则计数值+1
				if((10 == compset(data[i],l_it->first)) || (0 == compset(data[i],l_it->first))  )
					Ck_temp[l_it->first]++;
       //扫描完之后排除 非频繁项
		for(map_s::iterator l_it=Ck_temp.begin();l_it!=Ck_temp.end();l_it++ )
			if( Ck_temp[l_it->first] < minSup )
				Ck_temp.erase(l_it);
   }
   //如果是大于2的情况，扫描k-1的频繁项子集
   if(k>2){
      //每次都循环获取每个Ck的k-1子集元素
      //如{I1,I2,I3}C3的子集是{I1,I2} {I2,I3} {I3,I4}
      //如果Ck的子集不在k-1的频繁项子集中，则去掉该Ck项
      for(map_s::iterator l_it=Ck_temp.begin();l_it!=Ck_temp.end();l_it++ ){
         int flag;
         for(std::set<std::string>::iterator s_it=l_it->first.begin();s_it!=l_it->first.end();s_it++ ){
           //开始求子集
           //首先把当前Ck项的集合保存
           s_temp=l_it->first;
           //去掉一个元素，即是它的k-1子集
           s_temp.erase(*s_it);
           //遍历频繁项集合L，看看是不是在频繁集中
           flag=1;
           for(int i=0;i<L.size();i++){
             //如果K-1子集在频繁项集中存在，则保留
             if(compset(s_temp,L[i])==0){
            	 flag=0;
            	 break;
             }
           }
           //如果找到了哪怕一个k-1子集项不在频繁项集中，直接退出
           if(flag) break;
         }
         //只有所有的k-1子集在频繁项集中，才保留该Ck项
         if(flag) Ck_temp.erase(l_it);
      }
   }
#if(SHOW_CK)
   std::cout<<"由L"<<k-1<<"产生的候选集C"<<k<<"   "<<"cout数(k=2以上不做计数)"<<std::endl;
   for( map_s::iterator l_it=Ck_temp.begin();l_it!=Ck_temp.end();l_it++){
        for( std::set<std::string>::iterator s_it=l_it->first.begin();s_it!=l_it->first.end();s_it++ )
        	std::cout<<*s_it<<"  ";
        std::cout<<l_it->second<<std::endl;
   }
#endif
	return Ck_temp;
}

int find_heartbeat(int slice_num, cluster_vector* clu, double confi,int* heart){
	int min_support = slice_num*confi;
	std::vector<std::set<std::string> > data;
	std::vector<std::set<std::string> > L;
	std::vector<std::string> data2;
	std::set<std::string> s;
	map_s ck ;//候选集Ck
	map_s lk ; //频繁项集Lk
	std::map<int,int> show;
	show.clear();
	for(int i=0;i<slice_num;i++){
		s.clear();
		for(int j=0;j<clu[i].pkt_num;j++){
			int tmp = clu[i].pkt_tag[j]?clu[i].pkt_size[j]:-clu[i].pkt_size[j];
			char digit[100];
			sprintf(digit,"%d",tmp);
			s.insert(std::string(digit));
			data2.push_back(std::string(digit));    // 项可能重复
		}
		data.push_back(s);
	}
	for(int j=0; j<data2.size();j++){
		int flag = 1;
		for(map_s::iterator l_it=ck.begin();l_it!=ck.end();l_it++){
			if((l_it->first).find(data2[j]) != (l_it->first).end()){
				ck[l_it->first]++;
				flag=0;
				break;
			}
		}
		if(flag){
			s.clear();
		    s.insert(data2[j]);
		    ck.insert(std::pair<std::set<std::string>,int>(s,1));
		}
	}
	for(map_s::iterator l_it=ck.begin();l_it!=ck.end();l_it++)
		if(l_it->second<min_support)  ck.erase(l_it);


// add
#if(SHOW_CK)
	std::cout<<"C1候选集:"<<std::endl;
	std::cout<<"项集"<<"     "<<"支持度计数"<<std::endl;
	for(map_s::iterator l_it=Ck.begin();l_it!=Ck.end();l_it++){
		for(std::set<std::string>::iterator s_it=(l_it->first).begin(); s_it!=(l_it->first).end(); s_it++)
			std::cout<<*s_it<<" "<<l_it->second<<std::endl;
	}
#endif
	int f_count=2;
	while(f_count){
		printf("f_count is %d\n", f_count);
		//将Ck内的k-1频繁集全部保存到L集中
		for(map_s::iterator l_it=ck.begin();l_it!=ck.end();l_it++)
			L.push_back(l_it->first);
	      //获取Ck集，已清除掉小于支持度的候选集
		ck = apriori_gen(ck,f_count,data,L,min_support);
		if(ck.empty()) break;
		else f_count++;
	}
#if(SHOW_CK_FINAL)
	std::cout<<"最终的频繁集集合"<<std::endl;
	for(int i=0;i<L.size();i++){
		for( std::set<std::string>::iterator s_it=L[i].begin(); s_it!=L[i].end(); s_it++)
			std::cout<<*s_it<<" ";
	std::cout<<std::endl;
	}
#endif
	int cnt = 0;
	for(std::set<std::string>::iterator s_it=L[L.size()-1].begin(); s_it!=L[L.size()-1].end(); s_it++,cnt++)
		heart[cnt]=atoi((*s_it).c_str());

#if(SHOW_CK)
	printf("the heatbeat is\n");
	for(int i=0;i<cnt;i++)
		printf("%d ", heart[i]);
	printf("\n");
#endif
	return cnt;
}


/*
 * apriori_cut_heartbeat.h
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#ifndef APRIORI_CUT_HEARTBEAT_H_
#define APRIORI_CUT_HEARTBEAT_H_
#include <string>
#include <map>
#include <set>
#include <vector>
typedef std::map<std::set<std::string>,int> map_s;

void Delete(map_s &Ck);
int compset(std::set<std::string> s1,std::set<std::string> s2);
map_s apriori_gen(map_s &Ck,int k,std::vector<std::set<std::string> > data,  std::vector<std::set<std::string> >  L,int minSup);
int find_heartbeat(int slice_num, cluster_vector* clu, double confi, int* heart);



#endif /* APRIORI_CUT_HEARTBEAT_H_ */

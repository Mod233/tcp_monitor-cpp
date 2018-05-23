/*
 * judge_out_control.h
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#ifndef JUDGE_OUT_CONTROL_H_
#define JUDGE_OUT_CONTROL_H_
#include "stream_to_vector.h"

int judge_out_control(flow_vector stream_vector, cluster_vector* clu);

int time_slice(flow_vector stream_vector, double delta_time, cluster_vector* clu);

int judge_tcp(flow_vector stream_vector);

#endif /* JUDGE_OUT_CONTROL_H_ */

/*
 * init.h
 *
 *  Created on: May 26, 2018
 *      Author: csober
 */

#ifndef SRC_INIT_H_
#define SRC_INIT_H_
#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#define HASH_SIZE 20
static u_char xo[HASH_SIZE] = {77,22,182,100,238,136,249,164,109,222,190,45,251,120,99,107,151,187,29,145};
static u_char perm[HASH_SIZE] = {0,16,15,14,5,4,18,2,9,17,7,8,11,12,10,1,19,6,3,13};


static u_int mkhash (u_int src, u_int dest);


#endif /* SRC_INIT_H_ */

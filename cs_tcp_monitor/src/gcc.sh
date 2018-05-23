#!/bin/bash

g++ judge_out_control.cpp stream_to_vector.cpp apriori_cut_heartbeat.cpp main.cpp -l pcap -o https.out

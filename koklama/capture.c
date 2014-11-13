//
//  capture.c
//  koklama
//
//  Created by System Administrator on 02/11/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#include "capture.h"

void capture_loop_cb(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pkt) {
        // pcap_t *handle = (pcap_t *)arg;
        fprintf(stdout,"%d\n",pkthdr->caplen);
}
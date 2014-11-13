//
//  capture.h
//  koklama
//
//  Created by System Administrator on 02/11/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#ifndef __koklama__capture__
#define __koklama__capture__

#include <stdio.h>
#include <pcap.h>

void capture_loop_cb(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pkt);

#endif /* defined(__koklama__capture__) */

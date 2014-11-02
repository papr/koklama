//
//  utils.h
//  koklama
//
//  Created by System Administrator on 02/11/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#ifndef __koklama__utils__
#define __koklama__utils__

#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>

char *chooseKoklamaDevice(char **errbuf);
pcap_t *openDeviceAndApplyFilter(char *dev, char *filter,char **errbuf);

#endif /* defined(__koklama__utils__) */

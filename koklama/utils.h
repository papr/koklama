//
//  utils.h
//  koklama
//
//  Created by System Administrator on 02/11/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#ifndef __koklama__utils__
#define __koklama__utils__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>

char *chooseKoklamaDevice(char **errbuf);
pcap_t *openLiveDeviceAndApplyFilter(char *dev, bool monitormode, char *filter,char **errbuf);
pcap_t *openCaptureFile(char *path,char **errbuf);

#endif /* defined(__koklama__utils__) */

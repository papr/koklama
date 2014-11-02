//
//  main.c
//  koklama
//
//  Created by Pablo Prietz on 30.10.14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>

#include "utils.h"

int main(int argc, char *argv[])
{

        char *errbuf = NULL;
        char *dev = chooseKoklamaDevice(&errbuf);

        if (dev == NULL) {
                printf("%s\n",errbuf);
                free(errbuf);
                return(2);
        }

        pcap_t *handle = openDeviceAndApplyFilter(dev, "port 80", &errbuf);

        if (handle == NULL) {
                printf("%s\n",errbuf);
                return(2);
        }

        pcap_close(handle);
        free(errbuf);
        
        return(0);
}
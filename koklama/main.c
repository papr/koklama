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
#include "capture.h"

int main(int argc, char *argv[])
{

        char *errbuf = NULL;
        pcap_t *handle = NULL;

        char *dev = chooseKoklamaDevice(&errbuf);

        if (dev == NULL) {
                printf("%s\n",errbuf);
                return(2);
        }

        handle = openLiveDeviceAndApplyFilter(dev, true, "", &errbuf);

        if (dev != NULL) free(dev);

        if (handle == NULL) {
                printf("%s\n",errbuf);
                return(2);
        }


        pcap_loop(handle, -1, capture_loop_cb, (u_char *)handle);

        // turn off monitor modeif it was turned on before
        // if (suc == 1) { pcap_set_rfmon(handle, false); }

        pcap_close(handle);

        return(0);
}
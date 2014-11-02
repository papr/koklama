//
//  utils.c
//  koklama
//
//  Created by System Administrator on 02/11/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#include "utils.h"

char *chooseKoklamaDevice(char **custerrbuf) {

        char errbuf[PCAP_ERRBUF_SIZE];

        // look up all devices
        pcap_if_t *devlist;
        int searchsuc = pcap_findalldevs(&devlist,errbuf);

        // check for failure
        if (searchsuc == -1) {
                asprintf(custerrbuf, "Search failure: %s\n", errbuf);
                return NULL;
        }

        // check if list is empty
        if (devlist == NULL) {
                asprintf(custerrbuf, "No devices found. Privileges may not be given.\n");
                return NULL;
        }

        pcap_if_t *sniffdev = NULL;

        bool validdev = false;
        while (!validdev) {

                // enumerate all found devices
                uint counter = 1;
                pcap_if_t *curdev = devlist;

                printf("Choose a device to koklama on:\n");
                while (curdev != NULL) {
                        printf("\t%u) %s\n", counter,curdev->name);
                        curdev = curdev->next;
                        counter++;
                }
                printf("\n\t0) Cancel\n");

                // read choice
                int choosendev = -1;
                while(scanf("%d", &choosendev) == 0) {
                        while (getchar() != '\n'); // clear bad input
                }

                if (choosendev == 0) {
                        *custerrbuf = "Device selection canceled.";
                        return NULL;
                }
                else if (choosendev > 0 && choosendev < counter) {

                        counter = 1;
                        curdev = devlist;
                        while (curdev != NULL) {
                                if (counter == choosendev) {
                                        sniffdev = curdev;
                                        printf("Choosen device: %s\n", sniffdev->name);
                                        validdev = true;
                                        break;
                                }
                                curdev = curdev->next;
                                counter++;
                        }
                }
                if (!validdev) {
                        printf("Something went wrong while choosing a device. Please try again.\n\n");
                }
        }
        return sniffdev->name;
}

pcap_t *openDeviceAndApplyFilter(char *dev, char *filter,char **custerrbuf) {

	char errbuf[PCAP_ERRBUF_SIZE];

        struct bpf_program fp;          /* The compiled filter expression */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                asprintf(custerrbuf, "Can't get netmask for device %s\n", dev);
                net = 0;
                mask = 0;
        }

        // open device
        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL) {
                asprintf(custerrbuf, "Couldn't open device %s: %s\n", dev, errbuf);
                return handle;
        }

        // check if ethernet headers are available
        if (pcap_datalink(handle) != DLT_EN10MB) {
                asprintf(custerrbuf, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
                return NULL;
        }

        // compile regular expression to real filter
        if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                asprintf(custerrbuf, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                return NULL;
        }
        
        // apply filter
        if (pcap_setfilter(handle, &fp) == -1) {
                asprintf(custerrbuf, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                return NULL;
        }

        return handle;
}
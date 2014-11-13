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
        pcap_if_t *devlist;
        pcap_if_t *sniffdev = NULL;
        bool validdev = false;
        char *sniffname = NULL;

        // look up all devices
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

        sniffname = malloc(sizeof(char)*strlen(sniffdev->name));
        strcpy(sniffname,sniffdev->name);

        pcap_freealldevs(devlist);
        return sniffname;
}

pcap_t *openLiveDeviceAndApplyFilter(char *dev, bool monitormode, char *filter,char **custerrbuf) {

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
        pcap_t *handle = pcap_create(dev, errbuf);

        if (handle == NULL) {
                asprintf(custerrbuf, "Couldn't open device %s: %s\n", dev, errbuf);
                return handle;
        }

        pcap_set_snaplen(handle, BUFSIZ);
        pcap_set_promisc(handle, true);
        pcap_set_timeout(handle, 1000);

        if (monitormode) {
                int suc = pcap_can_set_rfmon(handle);
                switch (suc) {
                        case 0:
                                fprintf(stderr, "Monitor mode cannot be set\n");
                                break;
                        case 1:
                                suc = pcap_set_rfmon(handle, true);
                                fprintf(stderr, "Trying to activate monitor mode\n");
                                if (suc == PCAP_ERROR_ACTIVATED)
                                {
                                        fprintf(stderr, "Error: Handle already activated\n");
                                }
                                else { fprintf(stderr, "Monitor mode activated\n"); }
                                break;
                        case PCAP_ERROR_NO_SUCH_DEVICE:
                                fprintf(stderr, "Error: PCAP_ERROR_NO_SUCH_DEVICE\n");
                                break;
                        case PCAP_ERROR_PERM_DENIED:
                                fprintf(stderr, "Error: PCAP_ERROR_PERM_DENIED\n");
                                break;
                        case PCAP_ERROR_ACTIVATED:
                                fprintf(stderr, "Error: PCAP_ERROR_ACTIVATED\n");
                                break;
                        case PCAP_ERROR:
                                fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
                                break;
                        default:
                                fprintf(stderr, "Unknown error trying to set monitor mode");
                                break;
                }
        }

        pcap_activate(handle);

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

pcap_t *openCaptureFile(char *path,char **custerrbuf) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_offline(path, errbuf);
        if (handle == NULL) {
		asprintf(custerrbuf, "Could not open file %s: %s\n", path, errbuf);
        }
        return handle;
}

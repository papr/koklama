//
//  main.c
//  koklama
//
//  Created by Pablo Prietz on 30.10.14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

    // look up all devices
    pcap_if_t *devlist;
	int searchsuc = pcap_findalldevs(&devlist,errbuf);

    // check for failure
	if (searchsuc == -1) {
		fprintf(stderr, "Search failure: %s\n", errbuf);
		return(2);
	}

    // check if list is empty
	if (devlist == NULL) {
		printf("No devices found. Privileges may not be given.\n");
		return(0);
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

        // read choice
        uint choosendev = 0;
        scanf("%u", &choosendev);

        if (choosendev > 0 && choosendev < counter) {
            
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

    struct bpf_program fp;          /* The compiled filter expression */
    char filter_exp[] = "port 80";     /* The filter expression */
    bpf_u_int32 mask;               /* The netmask of our sniffing device */
    bpf_u_int32 net;                /* The IP of our sniffing device */
    struct pcap_pkthdr header;      /* The header that pcap gives us */
    const u_char *packet;           /* The actual packet */

    if (pcap_lookupnet(sniffdev->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", sniffdev->name);
        net = 0;
        mask = 0;
    }

    // open device
    pcap_t *handle = pcap_open_live(sniffdev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", sniffdev->name, errbuf);
        return(2);
    }

    // check if ethernet headers are available
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", sniffdev->name);
        return(2);
    }

    // compile regular expression to real filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // apply filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);

    pcap_close(handle);

	return(0);
}
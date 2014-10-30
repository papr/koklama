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

    pcap_if_t *sniffdev;
    
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
	return(0);
}
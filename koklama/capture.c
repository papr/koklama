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
        // int type = pcap_datalink(handle);, pcap_datalink_val_to_name(type)
        // fprintf(stdout,"%d\n",pkthdr->caplen);

        // radio tap header + radio tap data
        const struct ieee80211_radiotap_header *rtphead;
        rtphead = (struct ieee80211_radiotap_header*)pkt;

        // 802.11 header
        const u_char *frmctrlcharptr = pkt + rtphead->it_len;
	unsigned int *frmctrlptr = (unsigned int *)frmctrlcharptr;
        unsigned int frmctrl = *frmctrlptr; // frame control length 30bits
        frmctrl = frmctrl >> 12;
        frmctrl = frmctrl % 4;

        if (frmctrl == 2) {
                const u_char *addr1charptr = pkt + rtphead->it_len + 4;
		char macStr[18];

                snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                         addr1charptr[0], addr1charptr[1], addr1charptr[2], addr1charptr[3], addr1charptr[4], addr1charptr[5]);

                fprintf(stdout,"%s\n",macStr);
        }
}
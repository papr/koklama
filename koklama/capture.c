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

        // radio tap header + radio tap data
        const struct ieee80211_radiotap_header *rtphead;
        rtphead = (struct ieee80211_radiotap_header*)pkt;

        // 802.11 header
        const u_char *frmctrlcharptr = pkt + rtphead->it_len;
	unsigned int *frmctrlptr = (unsigned int *)frmctrlcharptr;
        unsigned int bitfick = ((*frmctrlptr >> 12) % 4);

        if (bitfick == 2) {
                u_char bits[16];
                memset(bits, 0, 16*sizeof(u_char));
                const u_char *addr1charptr = pkt + rtphead->it_len;
                const u_char *ptr = addr1charptr;
                for (int j=0; j<2; j++) {
                        ptr = ptr + j;
                        int i;
                        for(; *ptr != 0; ++ptr)
                        {
                                /* perform bitwise AND for every bit of the character */
                                for(i = 7; i >= 0; --i)
                                        bits[j*8+(7-i)] = (*ptr & 1 << i) ? '1' : '0';
                        }
                }
                fprintf(stdout, "%s\n",bits);
                /*
                char macStr[18];

                snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                         addr1charptr[0], addr1charptr[1], addr1charptr[2], addr1charptr[3], addr1charptr[4], addr1charptr[5]);

                fprintf(stdout,"%s\n",macStr);
                 */
        }
}
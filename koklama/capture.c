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
        const u_char *frmref = pkt + rtphead->it_len;

        const uint16_t *frmctrl = (const uint16_t *)frmref;

        uint16_t is_encrypt_flag = 2;
        uint16_t type_subtype_flag = 15360;
        uint16_t data_type_flag = 8192;

        // check if packet is encrypted
        if ((*frmctrl & is_encrypt_flag) != is_encrypt_flag)
        {
                // check if it is a data packet
                if (( (*frmctrl & type_subtype_flag) ^ data_type_flag) == 0)
                {
                        /* ethernet addesses
                         const struct ether_addr *addr1 = (const struct ether_addr *)(frmref + 4);
                         const struct ether_addr *addr2 = (const struct ether_addr *)(frmref + 10);
                         const struct ether_addr *addr3 = (const struct ether_addr *)(frmctrl + 16);
                         fprintf(stdout, "%s\t\t%s\t\t%s\n",ether_ntoa(addr1),ether_ntoa(addr2),ether_ntoa(addr3));
                         //*/

                        const struct ip *ipref = (const struct ip *)(frmref + 40);
                        /*
                        char src[64], dst[64];
                        inet_ntop(AF_INET,&ipref->ip_src,src,sizeof(src));
                        inet_ntop(AF_INET,&ipref->ip_dst,dst,sizeof(dst));
                        fprintf(stdout, "%s\t\t%s\n",src,dst);
                         //*/


                }
        }
}
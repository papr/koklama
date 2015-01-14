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
                        const struct ip *ipref;

                        for (int shift = 34; shift <= 40; shift += 2) {
                                ipref = (const struct ip *)(frmref + shift);
                                u_int ver = ipref->ip_v;
                                if (ver == 4) {

                                        u_char prot = ipref->ip_p;
                                        u_int8_t protnum = prot;

                                        if (protnum == 17) {

                                                //* ethernet addesses
                                                const struct ether_addr *addr1 = (const struct ether_addr *)(frmref + 4);
                                                const struct ether_addr *addr2 = (const struct ether_addr *)(frmref + 10);
                                                const struct ether_addr *addr3 = (const struct ether_addr *)(frmref + 13);
                                                fprintf(stdout, "%s\t\t",ether_ntoa(addr1));
                                                fprintf(stdout, "%s\t\t",ether_ntoa(addr2));
                                                fprintf(stdout, "%s\t\t",ether_ntoa(addr3));
                                                //*/
                                                
                                                //*
                                                char src[64], dst[64];
                                                inet_ntop(AF_INET,&ipref->ip_src,src,sizeof(src));
                                                inet_ntop(AF_INET,&ipref->ip_dst,dst,sizeof(dst));
                                                fprintf(stdout, "%s\t\t%s\t%hu\n",src,dst,ipref->ip_off);
                                                //*/

                                                /*
                                                char host[1024];
                                                char service[20];
                                                const struct sockaddr sa;

                                                getnameinfo(&sa, sizeof(&ipref->ip_src), host, sizeof(host), service, sizeof(service), 0);
                                                
                                                //*/

                                                const struct udphdr *udpref = (const struct udphdr *)(frmref + shift + (4*ipref->ip_hl));
                                                fprintf(stdout, "%hu\t\t%hu\n",ntohs(udpref->uh_sport), ntohs(udpref->uh_dport));

						//*
                                                const u_char *data = frmref + shift + (4*ipref->ip_hl) + sizeof(udpref);
                                                u_short datalen = ntohs(udpref->uh_ulen) - sizeof(udpref);
                                                fprintf(stdout, "%hu\t%lu\t%hu\n",ntohs(udpref->uh_ulen),sizeof(udpref),datalen);
                                                u_char datastr[datalen];
                                                memcpy(datastr, data, sizeof(datastr));
                                                fprintf(stdout, "%s\n--------------------------------------\n",datastr);
                                                 //*/

                                        }

                                        break;
                                }
                        }
                }
        }
}
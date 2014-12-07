//
//  definitions.h
//  koklama
//
//  Created by System Administrator on 07/12/14.
//  Copyright (c) 2014 Emrah Ayaz & Pablo Prietz. All rights reserved.
//

#ifndef koklama_definitions_h
#define koklama_definitions_h

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct rtapdata {
        uint8_t  antsignal;
        uint8_t  pad_for_tx_attentuation; // <-- added
        uint16_t tx_attenuation;
        uint8_t  flags;
        uint8_t  pad_for_rx_flags;        // <-- added
        uint16_t rx_flags;
} __attribute__ ((packed));

#endif

//
// Created by jdl on 27/01/16.
//

#ifndef UDPHELPER
#define UDPHELPER

#define UDPHDRSIZE 8 /* Header size */

struct udp_header {
    unsigned int udph_srcport:16;
    unsigned int udph_destport:16;
    unsigned int udph_len:16;
    unsigned int udph_chksum:16;
};

void build_udp_header(struct udp_header *udpHeader, unsigned short sport, unsigned short dport, unsigned short paylsize);

#endif

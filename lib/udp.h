//
// Created by jdl on 27/01/16.
//

#ifndef UDP
#define UDP

#define UDPHDRSIZE 8 /* Header size */

struct UdpHeader {
    unsigned int udph_srcport:16;
    unsigned int udph_destport:16;
    unsigned int udph_len:16;
    unsigned int udph_chksum:16;
    unsigned char data[0];
};

struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, unsigned short len, unsigned long paysize,
                                    unsigned char *payload);

void injects_udp_header(unsigned char *buff,unsigned short srcp, unsigned short dstp, unsigned short len);

#endif

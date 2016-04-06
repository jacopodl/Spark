//
// Created by root on 06/04/16.
//

#ifndef SPARK_ARP
#define SPARK_ARP

#define ARPHWT_ETH      1
#define ARPHWT_EXPETH   2
#define ARPHWT_AX25     3
#define ARPHWT_PRONET   4
#define ARPHWT_CHAOS    5
#define ARPHWT_ARCNET   7
#define ARPHWT_FRAMER   15
#define ARPHWT_ATM      16
#define ARPHWT_HDLC     17
#define ARPHWT_FIBRE    18
#define ARPHWT_ARPSEC   30
#define ARPHWT_IPSECT   31
#define ARPHWT_INFINIB  32

#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
#define ARPOP_REQREV    3
#define ARPOP_REPREV    4


struct ArpHeader {
    unsigned short hw_type;
    unsigned short proto;
    unsigned char hwalen;
    unsigned char pralen;
    unsigned short opcode;
    unsigned data[0];
};

struct ArpHeader *injects_arp_header(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct sockaddr *shwaddr, struct sockaddr *spraddr,
                                     struct sockaddr *dhwaddr, struct sockaddr *dpraddr);

#endif

//
// Created by root on 01/04/16.
//

#ifndef TCP
#define TCP

#define TCPHDRSIZE  20
#define TCPSTDOFF   5   // (TCPHDRSIZE/(DWORD(32Bit)/8))
#define TCPOPTSIZE  40
#define TCPMSSDEF   536


// Option
#define TCPOPT_EOPLIST  0
#define TCPOPT_NOOP     1
#define TCPOPT_MSS      2
#define TCPOPT_WSOP     3
#define TCPOPT_SACKP    4
#define TCPOPT_SACK     5
#define TCPOPT_ECHO     6
#define TCPOPT_ECHOR    7
#define TCPOPT_TSOPT    8
#define TCPOPT_POCP     9
#define TCPOPT_POSP     10
#define TCPOPT_CC       11
#define TCPOPT_CCNEW    12
#define TCPOPT_CCECHO   13
#define TCPOPT_ACR      14
#define TCPOPT_ACD      15
#define TCPOPT_MD5S     19
#define TCPOPT_QUICKSR  27
#define TCPOPT_USERTOUT 28
#define TCPOPT_TCPAO    29

struct TcpHeader {
    unsigned short src;
    unsigned short dst;
    unsigned int seq;
    unsigned int ackseq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ecn_n:1;
    unsigned char rsv:3;
    unsigned char offset:4;
    // Control Bits
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    // Explicit Congestion Notification
    unsigned char ecn_e:1;
    unsigned char ecn_c:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char offset:4;
    unsigned char rsv:3;
    unsigned char ecn_n:1;
    // Explicit Congestion Notification
    unsigned char ecn_c:1;
    unsigned char ecn_e:1;
    // Control Bits
    unsigned char urg:1;
    unsigned char ack:1;
    unsigned char psh:1;
    unsigned char rst:1;
    unsigned char syn:1;
    unsigned char fin:1;
#endif
    unsigned short window;
    unsigned short checksum;
    unsigned short urp;
    unsigned char data[0];
};

struct TcpHeader *build_tcp_packet(unsigned short srcp, unsigned short dstp, unsigned long paysize,
                                   unsigned char *payload);

struct TcpHeader *injects_tcp_header(unsigned char *buff, unsigned short srcp, unsigned short dstp);

unsigned short tcp_checksum4(struct TcpHeader *TcpHeader, struct Ipv4Header *ipv4Header);

#endif

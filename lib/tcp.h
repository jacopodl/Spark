/*
* <tcp, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SPARK_TCP
#define SPARK_TCP

#include "ipv4.h"

#define TCPHDRSIZE  20
#define TCPHDRLEN   5   // (TCPHDRSIZE / (DWORD/8))
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
    unsigned int seqn;
    unsigned int ackn;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ecn_n:1;
    unsigned char rsv:3;
    unsigned char offset:4;
    unsigned char flags[0];
#define TCPCWR      0x80
#define TCPECNE     0x40
#define TCPURG      0x20
#define TCPACK      0x10
#define TCPPSH      0x08
#define TCPRST      0x04
#define TCPSYN      0x02
#define TCPFIN      0x01
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
    unsigned char flags[0];
#define TCPCWR      0x01
#define TCPECNE     0x02
#define TCPURG      0x04
#define TCPACK      0x08
#define TCPPSH      0x10
#define TCPRST      0x20
#define TCPSYN      0x40
#define TCPFIN      0x80
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

struct TcpHeader *build_tcp_packet(unsigned short src, unsigned short dst, unsigned int seqn,
                                   unsigned int ackn, unsigned char flags,
                                   unsigned short window, unsigned short urgp, struct Ipv4Header *ipv4Header,
                                   unsigned long paysize,
                                   unsigned char *payload);

struct TcpHeader *injects_tcp_header(unsigned char *buff, unsigned short src, unsigned short dst, unsigned int seqn,
                                     unsigned int ackn, unsigned char flags,
                                     unsigned short window, unsigned short urgp);

unsigned short tcp_checksum4(struct TcpHeader *TcpHeader, struct Ipv4Header *ipv4Header);

#endif

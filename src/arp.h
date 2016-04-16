/*
* <arp, part of Spark.>
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

#ifndef SPARK_ARP_H
#define SPARK_ARP_H

#include "ethernet.h"
#include "ipv4.h"

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
#define ARPOP_REVREQ    3
#define ARPOP_REVREP    4

#define ARPHDRSIZE          8
#define ARPPKTETHIP4SIZE    (ARPHDRSIZE + ((ETHHWASIZE+IPV4ADDRLEN)*2))

struct ArpHeader {
    unsigned short hw_type;
    unsigned short proto;
    unsigned char hwalen;
    unsigned char pralen;
    unsigned short opcode;
    unsigned char data[];
};

struct ArpHeader *injects_arp_packet(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct sockaddr *shwaddr, struct sockaddr *spraddr,
                                     struct sockaddr *dhwaddr, struct sockaddr *dpraddr);

struct ArpHeader *injects_arp_ethip4_packet(unsigned char *buff, unsigned short opcode, struct sockaddr *shwaddr,
                                            struct in_addr *spraddr, struct sockaddr *dhwaddr,
                                            struct in_addr *dpraddr);

bool arp_ethip4_resolver(struct llOptions *llo, unsigned short opcode, struct sockaddr *shwaddr,
                         struct in_addr *spraddr, struct sockaddr *dhwaddr, struct in_addr *dpraddr);
#endif

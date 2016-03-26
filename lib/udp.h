/*
* <udp, part of Spark.>
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

#ifndef UDP
#define UDP

#include "ethernet.h"
#include "ipv4.h"

#define UDPHDRSIZE  8                                           // Header size
#define UDP4MINLEN  (UDPHDRSIZE + 0)                            // UDP over IPv4 min len
#define UDP4MAXLEN  (ETHMAXPAYL - (IPV4HDRSIZE + UDPHDRSIZE))   // UDP over IPv4 max len

struct UdpHeader {
    unsigned short udp_srcport;
    unsigned short udp_dstport;
    unsigned short udp_len;
    unsigned short udp_cheksum;
    unsigned char data[0];
};

struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, unsigned short len, unsigned long paysize,
                                    unsigned char *payload);

unsigned short udp4_checksum(struct UdpHeader *udpHeader, struct Ipv4Header *ipv4Header);

void injects_udp_header(unsigned char *buff,unsigned short srcp, unsigned short dstp, unsigned short len);

#endif

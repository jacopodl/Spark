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

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "ipv4.h"
#include "udp.h"

struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, unsigned short len,
                                   struct Ipv4Header *ipv4Header, unsigned long paysize,
                                   unsigned char *payload) {
    unsigned long size = UDPHDRSIZE + paysize;
    struct UdpHeader *ret = (struct UdpHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    injects_udp_header((unsigned char *) ret, srcp, dstp, len);
    if (payload != NULL) {
        memcpy(ret->data, payload, paysize);
        ret->checksum = udp_checksum4(ret,ipv4Header);
    }
    return ret;
}

unsigned short udp_checksum4(struct UdpHeader *udpHeader, struct Ipv4Header *ipv4Header) {
    unsigned short *buf = (unsigned short *) udpHeader;
    register unsigned int sum = 0;
    udpHeader->checksum = 0;

    // Add the pseudo-header
    sum += *(((unsigned short *) &ipv4Header->saddr));
    sum += *(((unsigned short *) &ipv4Header->saddr) + 1);
    sum += *(((unsigned short *) &ipv4Header->daddr));
    sum += *(((unsigned short *) &ipv4Header->daddr) + 1);
    sum += htons(ipv4Header->protocol) + udpHeader->len;

    for (int i = 0; i < ntohs(udpHeader->len); i += 2)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = ~sum;
    return (unsigned short) (sum == 0 ? 0xFFFF : sum); // RFC 768
}

struct UdpHeader *injects_udp_header(unsigned char *buff, unsigned short srcp, unsigned short dstp,
                                     unsigned short len) {
    struct UdpHeader *ret = (struct UdpHeader *) buff;
    memset(ret, 0x00, UDPHDRSIZE);
    ret->srcport = htons(srcp);
    ret->dstport = htons(dstp);
    ret->len = htons(((unsigned short) UDPHDRSIZE) + len);
    return ret;
}

/*
 * Copyright (c) 2016 - 2017 Jacopo De Luca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <ip.h>
#include <udp.h>

struct UdpHeader *udp_build_packet(unsigned short srcp, unsigned short dstp, unsigned short paysize,
                                   unsigned char *payload) {
    unsigned long size = UDPHDRSIZE + paysize;
    struct UdpHeader *ret = (struct UdpHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    udp_inject_header((unsigned char *) ret, srcp, dstp, paysize);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

unsigned short udp_checksum(struct UdpHeader *udpHeader, struct Ipv4Header *ipv4Header) {
    unsigned short *buf = (unsigned short *) udpHeader;
    unsigned short udpl = ntohs(ipv4Header->len) - (unsigned short) (ipv4Header->ihl * 4);
    unsigned short length = udpl;
    register unsigned int sum = 0;

    udpHeader->checksum = 0;
    while (udpl > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        udpl -= 2;
    }

    if (udpl & 1)
        sum += *((unsigned char *) buf);

    // Add the pseudo-header
    sum += *(((unsigned short *) &ipv4Header->saddr));
    sum += *(((unsigned short *) &ipv4Header->saddr) + 1);
    sum += *(((unsigned short *) &ipv4Header->daddr));
    sum += *(((unsigned short *) &ipv4Header->daddr) + 1);
    sum += htons(0x11);
    sum += htons(length);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (unsigned short) ~sum;
}

struct UdpHeader *udp_inject_header(unsigned char *buf, unsigned short srcp, unsigned short dstp,
                                    unsigned short len) {
    struct UdpHeader *ret = (struct UdpHeader *) buf;
    memset(ret, 0x00, UDPHDRSIZE);
    ret->srcport = htons(srcp);
    ret->dstport = htons(dstp);
    ret->len = htons(((unsigned short) UDPHDRSIZE) + len);
    return ret;
}

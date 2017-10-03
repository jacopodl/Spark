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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <ip.h>
#include <icmp.h>

struct IcmpHeader *icmp_build_packet(unsigned char type, unsigned char code, unsigned short paysize,
                                      unsigned char *payload) {
    unsigned long size = ICMP4HDRSIZE + paysize;
    struct IcmpHeader *ret = (struct IcmpHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    icmp_inject_header((unsigned char *) ret, type, code);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct IcmpHeader *icmp_inject_echo_reply(unsigned char *buf, unsigned short id, unsigned short seqn) {
    struct IcmpHeader *icmp = icmp_inject_header(buf, ICMPTY_ECHO_REPLY, 0);
    icmp->echo.id = htons(id);
    icmp->echo.sqn = htons(seqn);
    return icmp;
}

struct IcmpHeader *icmp_inject_echo_request(unsigned char *buf, unsigned short id, unsigned short seqn) {
    struct IcmpHeader *icmp = icmp_inject_header(buf, ICMPTY_ECHO_REQUEST, 0);
    icmp->echo.id = htons(id);
    icmp->echo.sqn = htons(seqn);
    return icmp;
}

struct IcmpHeader *icmp_inject_header(unsigned char *buf, unsigned char type, unsigned char code) {
    struct IcmpHeader *ret = (struct IcmpHeader *) buf;
    memset(ret, 0x00, ICMP4HDRSIZE);
    ret->type = type;
    ret->code = code;
    return ret;
}

unsigned short icmp_checksum(struct IcmpHeader *icmpHeader, unsigned short paysize) {
    unsigned short *buf = (unsigned short *) icmpHeader;
    register unsigned int sum = 0;

    icmpHeader->chksum = 0;
    for (int i = 0; i < (ICMP4HDRSIZE + paysize); i += 2)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = ~sum;
    return (unsigned short) sum;
}

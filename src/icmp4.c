/*
* icmp, part of Spark.
* Copyright (C) 2015-2016 Jacopo De Luca
*
* This program is free library: you can redistribute it and/or modify
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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "ipv4.h"
#include "icmp4.h"

struct IcmpHeader *build_icmp4_echo_request(unsigned short id, unsigned short seqn, unsigned short paysize,
                                            unsigned char *payload) {
    unsigned long size = ICMP4HDRSIZE + paysize;
    struct IcmpHeader *icmp = (struct IcmpHeader *) malloc(size);
    if (icmp == NULL)
        return NULL;
    injects_icmp4_echo_request((unsigned char *) icmp, id, seqn);
    if (payload != NULL)
        memcpy(icmp->data, payload, paysize);
    else {
        int urandom = open("/dev/urandom", O_RDONLY);
        if (urandom == -1) {
            free(icmp);
            return NULL;
        }
        read(urandom, icmp->data, paysize);
        close(urandom);
    }
    icmp->chksum = icmp4_checksum(icmp, paysize);
    return icmp;
}

struct IcmpHeader *build_icmp4_packet(unsigned char type, unsigned char code, unsigned short paysize,
                                      unsigned char *payload) {
    unsigned long size = ICMP4HDRSIZE + paysize;
    struct IcmpHeader *ret = (struct IcmpHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    injects_icmp4_header((unsigned char *) ret, type, code);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct IcmpHeader *injects_icmp4_echo_request(unsigned char *buff, unsigned short id, unsigned short seqn) {
    struct IcmpHeader *icmp = injects_icmp4_header(buff, ICMPTY_ECHO_REQUEST, 0);
    icmp->echo.id = htons(id);
    icmp->echo.sqn = htons(seqn);
    return icmp;
}

struct IcmpHeader *injects_icmp4_header(unsigned char *buff, unsigned char type, unsigned char code) {
    struct IcmpHeader *ret = (struct IcmpHeader *) buff;
    memset(ret, 0x00, ICMP4HDRSIZE);
    ret->type = type;
    ret->code = code;
    return ret;
}

unsigned short icmp4_checksum(struct IcmpHeader *icmpHeader, unsigned short paysize) {
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

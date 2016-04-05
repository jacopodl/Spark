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

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "ipv4.h"
#include "tcp.h"

struct TcpHeader *build_tcp_packet(unsigned short src, unsigned short dst, unsigned int seqn,
                                   unsigned int ackn, unsigned char flags,
                                   unsigned short window, unsigned short urgp, unsigned long paysize,
                                   unsigned char *payload) {
    unsigned long size = TCPHDRSIZE + paysize;
    struct TcpHeader *ret = NULL;
    if ((ret = (struct TcpHeader *) malloc(size)) == NULL)
        return NULL;
    injects_tcp_header((unsigned char *) ret, src, dst, seqn, ackn, flags, window, urgp);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}


struct TcpHeader *injects_tcp_header(unsigned char *buff, unsigned short src, unsigned short dst, unsigned int seqn,
                                     unsigned int ackn, unsigned char flags,
                                     unsigned short window, unsigned short urgp) {
    struct TcpHeader *ret = (struct TcpHeader *) buff;
    memset(ret, 0x00, TCPHDRSIZE);
    ret->offset = TCPHDRLEN;
    ret->src = htons(src);
    ret->dst = htons(dst);
    ret->seqn = htonl(seqn);
    ret->ackn = htonl(ackn);
    *ret->flags = flags;
    ret->window = htons(window);
    ret->urp = htons(urgp);
    return ret;
}

unsigned short tcp_checksum4(struct TcpHeader *TcpHeader, struct Ipv4Header *ipv4Header)
{

}
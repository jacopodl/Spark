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

#include "udp.h"

struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, unsigned short len, unsigned long paysize,
                                    unsigned char *payload)
{
    unsigned long size = UDPHDRSIZE + paysize;
    struct UdpHeader *ret = (struct UdpHeader*)malloc(size);
    if(ret==NULL)
        return NULL;
    memset(ret,0x00,size);
    ret->udp_srcport = htons(srcp);
    ret->udp_dstport = htons(dstp);
    ret->udp_len=htons(UDPMINSIZE + len);
    if(payload!=NULL)
        memcpy(ret->data,payload,paysize);
    return ret;
}

void injects_udp_header(unsigned char *buff,unsigned short srcp, unsigned short dstp, unsigned short len)
{
    struct UdpHeader *ret = (struct UdpHeader*)buff;
    memset(ret,0x00,UDPHDRSIZE);
    ret->udp_srcport = htons(srcp);
    ret->udp_dstport = htons(dstp);
    ret->udp_len=htons(len);
}

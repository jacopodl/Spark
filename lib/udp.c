//
// Created by root on 28/01/16.
//

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "udp.h"

struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, unsigned short len, unsigned long paysize,
                                    unsigned char *payload)
{
    unsigned long size = sizeof(struct UdpHeader) + paysize;
    struct UdpHeader *ret = (struct UdpHeader*)malloc(size);
    if(ret==NULL)
        return NULL;
    memset(ret,0x00,size);
    ret->udph_srcport = htons(srcp);
    ret->udph_destport = htons(dstp);
    ret->udph_len=htons(len);
    if(payload!=NULL)
        memcpy(ret->data,payload,paysize);
    return ret;
}

void injects_udp_header(unsigned char *buff,unsigned short srcp, unsigned short dstp, unsigned short len)
{
    struct UdpHeader *ret = (struct UdpHeader*)buff;
    memset(ret,0x00,sizeof(struct UdpHeader));
    ret->udph_srcport = htons(srcp);
    ret->udph_destport = htons(dstp);
    ret->udph_len=htons(len);
}

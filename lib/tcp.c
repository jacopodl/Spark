//
// Created by root on 01/04/16.
//

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "tcp.h"

struct TcpHeader *build_tcp_packet(unsigned short srcp, unsigned short dstp, unsigned long paysize, unsigned char *payload)
{
    unsigned long size = TCPHDRSIZE + paysize;
    struct TcpHeader *ret = NULL;
    if((ret=(struct TcpHeader*)malloc(size))==NULL)
        return NULL;
    injects_tcp_header((unsigned char *) ret,srcp,dstp);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct TcpHeader *injects_tcp_header(unsigned char *buff, unsigned short srcp, unsigned short dstp)
{
    struct TcpHeader *ret = (struct TcpHeader *) buff;
    memset(ret, 0x00, TCPHDRSIZE);
    ret->src= htons(srcp);
    ret->dst= htons(dstp);
    ret->offset = TCPSTDOFF;
    ret->seq=htonl(1);
    ret->ackseq=0;
    ret->window=htons(2);
    ret->ecn_n=1;
    return ret;
}
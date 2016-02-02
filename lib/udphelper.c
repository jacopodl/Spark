//
// Created by root on 28/01/16.
//

#include <netinet/in.h>
#include "udphelper.h"

void build_udp_header(struct udp_header *udpHeader, unsigned short sport, unsigned short dport, unsigned short paylsize)
{
    udpHeader->udph_srcport=htons(sport);
    udpHeader->udph_destport=htons(dport);
    udpHeader->udph_len=htons((unsigned short int)UDPHDRSIZE+paylsize);
}

//
// Created by root on 06/04/16.
//

#include <string.h>

#include "netdevice.h"
#include "ethernet.h"
#include "arp.h"

struct ArpHeader *injects_arp_header(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct sockaddr *shwaddr, struct sockaddr *spraddr,
                                     struct sockaddr *dhwaddr, struct sockaddr *dpraddr) {
    struct ArpHeader *arp = (struct ArpHeader *) buff;
    unsigned char *data = (unsigned char *) arp->data;
    unsigned int tlen = sizeof(struct ArpHeader) + ((hwalen + pralen) * 2);
    memset(arp, 0x00, tlen);
    arp->hw_type = htons(ARPHWT_ETH);
    arp->proto = htons(ETHTYPE_IP);
    arp->hwalen = hwalen;
    arp->pralen = pralen;
    arp->opcode = htons(opcode);
    memcpy(data, shwaddr->sa_data, hwalen);
    data += hwalen;
    memcpy(data, spraddr->sa_data, pralen);
    data += pralen;
    memcpy(data, dhwaddr->sa_data, hwalen);
    data += hwalen;
    memcpy(data, dpraddr->sa_data, pralen);
    data += pralen;
    return arp;
}

bool arp_query4(struct llOptions *llo, unsigned short opcode, struct sockaddr *shwaddr, struct sockaddr *spraddr,
                struct sockaddr *dhwaddr, struct sockaddr *dpraddr) {
}
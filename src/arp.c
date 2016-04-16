/*
* <arp, part of Spark.>
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netdevice.h"
#include "ethernet.h"
#include "arp.h"

struct ArpHeader *injects_arp_packet(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct sockaddr *shwaddr, struct sockaddr *spraddr,
                                     struct sockaddr *dhwaddr, struct sockaddr *dpraddr) {
    struct ArpHeader *arp = (struct ArpHeader *) buff;
    unsigned char *data = (unsigned char *) arp->data;
    unsigned int tlen = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
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
    return arp;
}

struct ArpHeader *injects_arp_ethip4_packet(unsigned char *buff, unsigned short opcode, struct sockaddr *shwaddr,
                                            struct in_addr *spraddr, struct sockaddr *dhwaddr,
                                            struct in_addr *dpraddr) {
    struct sockaddr spr, dpr;
    memcpy(&spr.sa_data, &spraddr->s_addr, IPV4ADDRLEN);
    memcpy(&dpr.sa_data, &dpraddr->s_addr, IPV4ADDRLEN);
    return injects_arp_packet(buff, ETHHWASIZE, IPV4ADDRLEN, opcode, shwaddr, &spr, dhwaddr, &dpr);
}

bool arp_ethip4_resolver(struct llOptions *llo, unsigned short opcode, struct sockaddr *shwaddr,
                         struct in_addr *spraddr, struct sockaddr *dhwaddr, struct in_addr *dpraddr) {
    bool success = false;
    int ttry = 0;
    unsigned char *rcvb;
    struct EthHeader *eth, *r_eth;
    struct ArpHeader *arp, *r_arp;
    struct sockaddr ethbroad;
    if ((rcvb = (unsigned char *) malloc(llo->buffl)) == NULL)
        return false;
    build_ethbroad_addr(&ethbroad);
    eth = build_ethernet_packet(shwaddr, &ethbroad, ETHTYPE_ARP, ARPPKTETHIP4SIZE, NULL);
    if (eth == NULL)
        return false;
    arp = injects_arp_ethip4_packet(eth->data, opcode, shwaddr, spraddr, dhwaddr, dpraddr);
    llsend(eth, ETHHDRSIZE + ARPPKTETHIP4SIZE, llo);
    while (ttry < 10) {
        ttry++;
        if (llrecv(rcvb, llo) > 0) {
            r_eth = (struct EthHeader *) rcvb;
            if (memcmp(r_eth->dhwaddr, eth->shwaddr, ETHHWASIZE) != 0 || r_eth->eth_type != htons(ETHTYPE_ARP))
                continue;
            r_arp = (struct ArpHeader *) r_eth->data;
            if (memcmp((arp->data + ETHHWASIZE), (r_arp->data + (ETHHWASIZE + IPV4ADDRLEN + ETHHWASIZE)),
                       IPV4ADDRLEN) != 0)
                continue;
            switch (ntohs(r_arp->opcode)) {
                case ARPOP_REPLY:
                    memcpy(dhwaddr->sa_data, r_arp->data, ETHHWASIZE);
                    success = true;
                    break;
                case ARPOP_REVREP:
                    dpraddr->s_addr = *((unsigned int *) (r_arp->data + ETHHWASIZE));
                    success = true;
                    break;
                default:
                    success = false;
                    break;
            }
            break;
        }
    }
    free(rcvb);
    free(eth);
    return success;
}
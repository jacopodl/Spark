/*
* arp, part of Spark.
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

#include "datatype.h"
#include "llsock.h"
#include "arp.h"

struct ArpPacket *build_arp_packet(unsigned char hwalen, unsigned char pralen, unsigned short opcode,
                                   struct netaddr *shwaddr, struct netaddr *spraddr, struct netaddr *dhwaddr,
                                   struct netaddr *dpraddr) {
    unsigned long size = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    struct ArpPacket *arp = (struct ArpPacket *) malloc(size);
    if (arp == NULL)
        return NULL;
    injects_arp_packet((unsigned char *) arp, hwalen, pralen, opcode, shwaddr, spraddr, dhwaddr, dpraddr);
    return arp;
}

struct ArpPacket *injects_arp_packet(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct netaddr *shwaddr, struct netaddr *spraddr,
                                     struct netaddr *dhwaddr, struct netaddr *dpraddr) {
    struct ArpPacket *arp = (struct ArpPacket *) buff;
    unsigned char *data = (unsigned char *) arp->data;
    unsigned int tlen = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    memset(arp, 0x00, tlen);
    arp->hw_type = htons(ARPHWT_ETH);
    arp->proto = htons(ETHTYPE_IP);
    arp->hwalen = hwalen;
    arp->pralen = pralen;
    arp->opcode = htons(opcode);
    if (shwaddr != NULL)
        memcpy(data, shwaddr->na_data, hwalen);
    data += hwalen;
    if (spraddr != NULL)
        memcpy(data, spraddr->na_data, pralen);
    data += pralen;
    if (dhwaddr != NULL)
        memcpy(data, dhwaddr->na_data, hwalen);
    data += hwalen;
    if (dpraddr != NULL)
        memcpy(data, dpraddr->na_data, pralen);
    return arp;
}

struct ArpPacket *injects_arp_reply(unsigned char *buff, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                    struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return injects_arp_packet(buff, ETHHWASIZE, IPV4ADDRLEN, ARPOP_REPLY, (struct netaddr *) shwaddr,
                              (struct netaddr *) spraddr, (struct netaddr *) dhwaddr, (struct netaddr *) dpraddr);
}

struct ArpPacket *injects_arp_request(unsigned char *buff, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                      struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return injects_arp_packet(buff, ETHHWASIZE, IPV4ADDRLEN, ARPOP_REQUEST, (struct netaddr *) shwaddr,
                              (struct netaddr *) spraddr, (struct netaddr *) dhwaddr, (struct netaddr *) dpraddr);
}

int arp_resolver(struct llSockInfo *llsi, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                 struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    unsigned char wbuff[ETHHDRSIZE + ARPETHIPLEN];
    struct EthHeader *eth;
    struct EthHeader *r_eth;
    struct ArpPacket *arp;
    struct ArpPacket *r_arp;
    struct netaddr_mac ethbroad;

    struct timeval tv;
    int success = 0;
    int packet = 0;
    int attempts = ARPRESOLVER_ATTEMPTS;

    fd_set fdset;

    build_ethbroad_addr(&ethbroad);
    eth = injects_ethernet_header(wbuff, shwaddr, &ethbroad, ETHTYPE_ARP);
    if ((r_eth = (struct EthHeader *) malloc(llsi->buffl)) == NULL)
        return -1;
    arp = injects_arp_packet(eth->data, ETHHWASIZE, IPV4ADDRLEN, ARPOP_REQUEST, (struct netaddr *) shwaddr,
                             (struct netaddr *) spraddr, NULL, (struct netaddr *) dpraddr);

    while (attempts-- > 0) {
        if (llsend(eth, ETHHDRSIZE + ARPETHIPLEN, llsi) < 0) {
            free(r_eth);
            return -1;
        }
        packet = ARPRESOLVER_PACKETS;
        tv.tv_sec = ARPRESOLVER_TIMEOUT_SEC;
        tv.tv_usec = ARPRESOLVER_TIMEOUT_USEC;
        while (packet-- > 0) {
            FD_ZERO(&fdset);
            FD_SET(llsi->sfd, &fdset);
            if ((success = select(llsi->sfd + 1, &fdset, NULL, NULL, &tv)) < 0) {
                free(r_eth);
                return -1;
            }
            if (success) {
                if (llrecv2(r_eth, llsi) < 0) {
                    free(r_eth);
                    return -1;
                }
                if (memcmp(r_eth->dhwaddr, eth->shwaddr, ETHHWASIZE) != 0 || r_eth->eth_type != htons(ETHTYPE_ARP))
                    continue;
                r_arp = (struct ArpPacket *) r_eth->data;
                if (memcmp(arp->data, (r_arp->data + (ETHHWASIZE + IPV4ADDRLEN)), ETHHWASIZE) != 0)
                    continue;
                if (ntohs(r_arp->opcode) == ARPOP_REPLY) {
                    memcpy(dhwaddr->mac, r_arp->data, ETHHWASIZE);
                    free(r_eth);
                    return 1;
                }
            }
            else
                break;
        }
    }
    free(r_eth);
    return 0;
}
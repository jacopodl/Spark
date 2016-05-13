/*
* <ethernet, part of Spark.>
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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include "datatype.h"
#include "ethernet.h"

bool ethcmp(struct netaddr_mac *mac1, struct netaddr_mac *mac2) {
    for (int i = 0; i < ETHHWASIZE; i++)
        if (mac1->mac[i] != mac2->mac[i])
            return false;
    return true;
}

bool parse_mac(char *hwstr, struct netaddr_mac *mac, bool bcast) {
    if (strlen(hwstr) >= MACSTRSIZE)
        return false;
    unsigned int hwaddr[ETHHWASIZE];
    if (sscanf(hwstr, "%x:%x:%x:%x:%x:%x", hwaddr, hwaddr + 1, hwaddr + 2, hwaddr + 3, hwaddr + 4, hwaddr + 5) != 6)
        return false;
    if (!bcast && hwaddr[0] & ~0xFE)
        return false;
    if (mac != NULL)
        for (int i = 0; i < ETHHWASIZE; i++)
            mac->mac[i] = (char) hwaddr[i];
    return true;
}

char *get_strmac(struct netaddr_mac *mac, bool _static) {
    static char static_buff[MACSTRSIZE];
    char *smac = static_buff;
    if (!_static) {
        if ((smac = (char *) malloc(MACSTRSIZE)) == NULL)
            return NULL;
    }
    sprintf(smac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
            mac->mac[0], mac->mac[1],
            mac->mac[2], mac->mac[3],
            mac->mac[4], mac->mac[5]);
    return smac;
}

char *get_serial(struct netaddr_mac *mac, bool _static) {
    static char static_buff[MACSTRHLFSIZE];
    char *serial = static_buff;
    if (!_static) {
        if ((serial = (char *) malloc(MACSTRHLFSIZE)) == NULL)
            return NULL;
    }
    sprintf(serial, "%.2X:%.2X:%.2X", mac->mac[3], mac->mac[4], mac->mac[5]);
    return serial;
}

char *get_vendor(struct netaddr_mac *mac, bool _static) {
    static char static_buff[MACSTRHLFSIZE];
    char *vendor = static_buff;
    if (!_static) {
        if ((vendor = (char *) malloc(MACSTRHLFSIZE)) == NULL)
            return NULL;
    }
    sprintf(vendor, "%.2X:%.2X:%.2X", mac->mac[0], mac->mac[1], mac->mac[2]);
    return vendor;
}

struct EthHeader *build_ethernet_packet(struct netaddr_mac *src, struct netaddr_mac *dst, unsigned short type,
                                        unsigned long paysize, unsigned char *payload) {
    unsigned long size = ETHHDRSIZE + paysize;
    struct EthHeader *ret = (struct EthHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    injects_ethernet_header((unsigned char *) ret, src, dst, type);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct EthHeader *injects_ethernet_header(unsigned char *buff, struct netaddr_mac *src, struct netaddr_mac *dst,
                                          unsigned short type) {
    struct EthHeader *ret = (struct EthHeader *) buff;
    memset(ret, 0x00, ETHHDRSIZE);
    memcpy(ret->dhwaddr, dst->mac, ETHHWASIZE);
    memcpy(ret->shwaddr, src->mac, ETHHWASIZE);
    ret->eth_type = htons(type);
    return ret;
}

inline void build_ethbroad_addr(struct netaddr_mac *mac) {
    memset(mac->mac, 0xFF, ETHHWASIZE);
}

void build_ethmulti_addr(struct netaddr_mac *mac, struct netaddr_ip *ip) {
    memset(mac->mac, 0x00, ETHHWASIZE);
    *((int *) mac->mac) = htonl(0x01005E00);
    mac->mac[5] = *(((unsigned char *) &ip->ip) + 3);
    mac->mac[4] = *(((unsigned char *) &ip->ip) + 2);
    mac->mac[3] = *(((unsigned char *) &ip->ip) + 1) & (char) 0x7F;
    return;
}

void rndmac(struct netaddr_mac *mac) {
/* The lsb of the MSB can not be set,
 * because those are multicast mac addr!
 */
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1)
        return;
    read(urandom, mac->mac, ETHHWASIZE);
    mac->mac[0] &= ((char) 0xFE);
    close(urandom);
}
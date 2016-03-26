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

#include "ethernet.h"

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr, bool bcast) {
    if (strlen(hwstr) >= MACSTRSIZE)
        return false;
    unsigned int hwaddr[ETHHWASIZE];
    if (sscanf(hwstr, "%x:%x:%x:%x:%x:%x", hwaddr, hwaddr + 1, hwaddr + 2, hwaddr + 3, hwaddr + 4, hwaddr + 5) != 6)
        return false;
    if (!bcast && hwaddr[0] & ~0xFE)
        return false;
    if (ret_sockaddr != NULL)
        for (int i = 0; i < ETHHWASIZE; i++)
            ret_sockaddr->sa_data[i] = (char) hwaddr[i];
    return true;
}

char *get_strhwaddr(struct sockaddr *hwa, bool _static) {
    static char static_buff[MACSTRSIZE];
    char *mac = static_buff;
    if (!_static) {
        if ((mac = (char *) malloc(MACSTRSIZE)) == NULL)
            return NULL;
    }
    sprintf(mac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
            (unsigned char) hwa->sa_data[0], (unsigned char) hwa->sa_data[1],
            (unsigned char) hwa->sa_data[2], (unsigned char) hwa->sa_data[3],
            (unsigned char) hwa->sa_data[4], (unsigned char) hwa->sa_data[5]);
    return mac;
}

struct EthHeader *build_ethernet_packet(struct sockaddr *src, struct sockaddr *dst, unsigned short type,
                                        unsigned long paysize, unsigned char *payload) {
    unsigned long size = ETHHDRSIZE + paysize;
    struct EthHeader *ret = (struct EthHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    memset(ret, 0x00, size);
    memcpy(ret->dhwaddr, dst->sa_data, ETHHWASIZE);
    memcpy(ret->shwaddr, src->sa_data, ETHHWASIZE);
    ret->eth_type = htons(type);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

inline void build_ethbroad_addr(struct sockaddr *addr) {
    memset(addr->sa_data, 0xFF, ETHHWASIZE);
}

void build_ethmulti_addr(struct sockaddr *hw, struct in_addr *ip) {
    memset(hw->sa_data, 0x00, ETHHWASIZE);
    *((int *) hw->sa_data) = htonl(0x01005E00);
    hw->sa_data[5] = *(((char *) &ip->s_addr) + 3);
    hw->sa_data[4] = *(((char *) &ip->s_addr) + 2);
    hw->sa_data[3] = *(((char *) &ip->s_addr) + 1) & (char) 0x7F;
    return;
}

void injects_ethernet_header(unsigned char *buff, struct sockaddr *src, struct sockaddr *dst, unsigned short type) {
    struct EthHeader *ret = (struct EthHeader *) buff;
    memset(ret, 0x00, ETHHDRSIZE);
    memcpy(ret->dhwaddr, dst->sa_data, ETHHWASIZE);
    memcpy(ret->shwaddr, src->sa_data, ETHHWASIZE);
    ret->eth_type = htons(type);
}

void rndhwaddr(struct sockaddr *mac) {
/* The lsb of the MSB can not be set,
 * because those are multicast mac addr!
 */
    memset(mac, 0x00, sizeof(struct sockaddr));
    FILE *urandom;
    urandom = fopen("/dev/urandom", "r");
    fread(mac->sa_data, 1, ETHHWASIZE, urandom);
    mac->sa_data[0] &= ((char) 0xFE);
    fclose(urandom);
}
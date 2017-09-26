/*
 * Copyright (c) 2016 - 2017 Jacopo De Luca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <time.h>

#include <datatype.h>
#include <ethernet.h>

bool ethcmp(struct netaddr_mac *mac1, struct netaddr_mac *mac2) {
    for (int i = 0; i < ETHHWASIZE; i++)
        if (mac1->mac[i] != mac2->mac[i])
            return false;
    return true;
}

inline bool isbcast_mac(struct netaddr_mac *mac) {
    return (mac->mac[0] + mac->mac[1] + mac->mac[2] + mac->mac[3] + mac->mac[4] + mac->mac[5]) == 0x5FA;
}

inline bool isempty_mac(struct netaddr_mac *mac) {
    return (mac->mac[0] + mac->mac[1] + mac->mac[2] + mac->mac[3] + mac->mac[4] + mac->mac[5]) == 0x00;
}

bool parse_mac(char *hwstr, struct netaddr_mac *mac, bool bcast) {
    if (strlen(hwstr) >= MACSTRLEN)
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
    static char static_buf[MACSTRLEN];
    char *smac = static_buf;
    if (!_static) {
        if ((smac = (char *) malloc(MACSTRLEN)) == NULL)
            return NULL;
    }
    return get_strmac_r(mac, smac);
}

char *get_strmac_r(struct netaddr_mac *mac, char *macstr) {
    sprintf(macstr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            mac->mac[0], mac->mac[1],
            mac->mac[2], mac->mac[3],
            mac->mac[4], mac->mac[5]);
    return macstr;
}

char *get_serial(struct netaddr_mac *mac, bool _static) {
    static char static_buf[MACSTRHLFLEN];
    char *serial = static_buf;
    if (!_static) {
        if ((serial = (char *) malloc(MACSTRHLFLEN)) == NULL)
            return NULL;
    }
    return get_serial_r(mac, serial);
}

char *get_serial_r(struct netaddr_mac *mac, char *sstr) {
    sprintf(sstr, "%.2x:%.2x:%.2x", mac->mac[3], mac->mac[4], mac->mac[5]);
    return sstr;
}

char *get_vendor(struct netaddr_mac *mac, bool _static) {
    static char static_buf[MACSTRHLFLEN];
    char *vendor = static_buf;
    if (!_static) {
        if ((vendor = (char *) malloc(MACSTRHLFLEN)) == NULL)
            return NULL;
    }
    return get_vendor_r(mac, vendor);
}

char *get_vendor_r(struct netaddr_mac *mac, char *vstr) {
    sprintf(vstr, "%.2x:%.2x:%.2x", mac->mac[0], mac->mac[1], mac->mac[2]);
    return vstr;
}

struct EthHeader *build_ethernet_packet(struct netaddr_mac *src, struct netaddr_mac *dst, unsigned short type,
                                        unsigned long paysize, unsigned char *payload) {
    unsigned long size = ETHHDRSIZE + paysize;
    struct EthHeader *ret;

    if (paysize > ETHMAXPAYL) {
        errno = EINVAL;
        return NULL;
    }

    if ((ret = (struct EthHeader *) malloc(size)) == NULL)
        return NULL;

    injects_ethernet_header((unsigned char *) ret, src, dst, type);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct EthHeader *injects_ethernet_header(unsigned char *buf, struct netaddr_mac *src, struct netaddr_mac *dst,
                                          unsigned short type) {
    struct EthHeader *ret = (struct EthHeader *) buf;
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
}

void rndmac(struct netaddr_mac *mac) {
/* The lsb of the MSB can not be set,
 * because those are multicast mac addr!
 */
    srand((unsigned int) clock());
    *((unsigned int *) mac->mac) = (unsigned int) rand();
    *((unsigned short *) (mac->mac + 4)) = (unsigned short) rand();
    mac->mac[0] &= ((char) 0xFE);
}
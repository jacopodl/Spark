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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include <datatype.h>
#include <ip.h>

inline bool ip_equals(struct netaddr_ip *ip1, struct netaddr_ip *ip2) {
    return ip1->ip == ip2->ip;
}

inline bool ip_isbcast(struct netaddr_ip *ip) {
    unsigned char *byte = (((unsigned char *) (&ip->ip)));
    return (byte[0] == 0xFF) && (byte[1] == 0xFF) && (byte[2] == 0xFF) && (byte[3] == 0xFF);
}

inline bool ip_isbcast2(struct netaddr_ip *ip, struct netaddr_ip *netmask) {
    return ip->ip == ((~netmask->ip) | ip->ip);
}

inline bool ip_isempty(struct netaddr_ip *ip) {
    return ip->ip == 0x00;
}

bool ip_isgreater(struct netaddr_ip *ip1, struct netaddr_ip *ip2) {
    return ((ip1->ip & 0xFF) << 24 | (ip1->ip >> 8 & 0xFF) << 16 | (ip1->ip >> 16 & 0xFF) << 8 |
            (ip1->ip >> 24 & 0xFF)) >
           ((ip2->ip & 0xFF) << 24 | (ip2->ip >> 8 & 0xFF) << 16 | (ip2->ip >> 16 & 0xFF) << 8 |
            (ip2->ip >> 24 & 0xFF));
}

bool ip_isless(struct netaddr_ip *ip1, struct netaddr_ip *ip2) {
    return ((ip1->ip & 0xFF) << 24 | (ip1->ip >> 8 & 0xFF) << 16 | (ip1->ip >> 16 & 0xFF) << 8 |
            (ip1->ip >> 24 & 0xFF)) <
           ((ip2->ip & 0xFF) << 24 | (ip2->ip >> 8 & 0xFF) << 16 | (ip2->ip >> 16 & 0xFF) << 8 |
            (ip2->ip >> 24 & 0xFF));
}

inline bool ip_ismcast(struct netaddr_ip *ip) {
    unsigned char fbyte = *(((unsigned char *) (&ip->ip)));
    return ((fbyte >= 0xE0) && (fbyte <= 0xEF));
}

inline bool ip_issame_subnet(struct netaddr_ip *addr1, struct netaddr_ip *addr2, struct netaddr_ip *netmask) {
    return (addr1->ip & netmask->ip) == (addr2->ip & netmask->ip);
}

bool ip_parse_addr(char *ipstr, struct netaddr_ip *ip) {
    unsigned int ipaddr[IPADDRSIZE];
    if (strlen(ipstr) >= IPSTRLEN)
        return false;
    if (sscanf(ipstr, "%u.%u.%u.%u", ipaddr, ipaddr + 1, ipaddr + 2, ipaddr + 3) != 4)
        return false;
    if (ipaddr[0] > 255 || ipaddr[1] > 255 || ipaddr[2] > 255 || ipaddr[3] > 255)
        return false;
    if (ip != NULL)
        ip->ip = (ipaddr[3] << 24 | ipaddr[2] << 16 | ipaddr[1] << 8 | ipaddr[0]);
    return true;
}

char *ip_getstr(struct netaddr_ip *ip, bool _static) {
    static char static_buf[IPSTRLEN];
    char *ipstr = static_buf;
    if (!_static) {
        if ((ipstr = (char *) malloc(IPSTRLEN)) == NULL)
            return NULL;
    }
    return ip_getstr_r(ip, ipstr);
}

inline char *ip_getstr_r(struct netaddr_ip *ip, char *ipstr) {
    sprintf(ipstr, "%u.%u.%u.%u", (ip->ip) & 0xFF, (ip->ip) >> 8 & 0xFF, (ip->ip) >> 16 & 0xFF, (ip->ip) >> 24 & 0xFF);
    return ipstr;
}

struct Ipv4Header *ip_build_packet(struct netaddr_ip *src, struct netaddr_ip *dst, unsigned char ihl,
                                   unsigned short id, unsigned char ttl, unsigned char proto, unsigned short paysize,
                                   unsigned char *payload) {
    unsigned long size = IPHDRSIZE + paysize;
    struct Ipv4Header *ret = (struct Ipv4Header *) malloc(size);
    if (ret == NULL)
        return NULL;
    ip_inject_header((unsigned char *) ret, src, dst, ihl, id, paysize, ttl, proto);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct Ipv4Header *ip_inject_header(unsigned char *buf, struct netaddr_ip *src, struct netaddr_ip *dst,
                                    unsigned char ihl, unsigned short id, unsigned short len, unsigned char ttl,
                                    unsigned char proto) {
    struct Ipv4Header *ipv4 = (struct Ipv4Header *) buf;
    memset(ipv4, 0x00, IPHDRSIZE);
    ipv4->version = IPVERSION;
    ipv4->ihl = ihl;
    ipv4->len = htons((unsigned short) IPHDRSIZE + len);
    ipv4->id = id;
    ipv4->frag_off = htons(IPV4_FLAGS_DONTFRAG);
    ipv4->ttl = ttl;
    ipv4->protocol = proto;
    ipv4->saddr = src->ip;
    ipv4->daddr = dst->ip;
    ipv4->checksum = ip_checksum(ipv4);
    return ipv4;
}

unsigned short ip_checksum(struct Ipv4Header *ipHeader) {
    unsigned short *buf = (unsigned short *) ipHeader;
    register unsigned int sum = 0;
    ipHeader->checksum = 0;
    for (int i = 0; i < IPHDRSIZE; sum += *buf++, i += 2);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) ~sum;
}

inline unsigned short ip_mkid() {
    srand((unsigned int) clock());
    return ((uint16_t) rand());
}

inline void ip_bcast(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *broadcast) {
    broadcast->ip = (~netmask->ip) | addr->ip;
}

inline void ip_netaddr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *net) {
    net->ip = addr->ip & netmask->ip;
}

inline void ip_wildcard(struct netaddr_ip *netmask, struct netaddr_ip *ret_wildcard) {
    ret_wildcard->ip = ~netmask->ip;
}

void ip_inc(struct netaddr_ip *ip) {
    unsigned char *byte = (unsigned char *) &ip->ip;
    for (int i = IPADDRSIZE - 1; i >= 0; i--)
        if (++byte[i] != 0x00)
            break;
}

void ip_rndaddr(struct netaddr_ip *ip) {
    srand((unsigned int) clock());
    ip->ip = (unsigned int) rand();
}
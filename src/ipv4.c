/*
 * Copyright (c) 2016-2017 Jacopo De Luca
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
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <datatype.h>
#include <ipv4.h>

inline bool ipv4cmp(struct netaddr_ip *ip1, struct netaddr_ip *ip2) {
    return ip1->ip == ip2->ip;
}

inline bool isbcast_ipv4(struct netaddr_ip *ip) {
    unsigned char *byte = (((unsigned char *) (&ip->ip)));
    return (byte[0] == 0xFF) && (byte[1] == 0xFF) && (byte[2] == 0xFF) && (byte[3] == 0xFF);
}

inline bool isbcast2_ipv4(struct netaddr_ip *ip, struct netaddr_ip *netmask) {
    return ip->ip == ((~netmask->ip) | ip->ip);
}

inline bool isempty_ipv4(struct netaddr_ip *ip) {
    return ip->ip == 0x00;
}

inline bool ismcast_ipv4(struct netaddr_ip *ip) {
    unsigned char fbyte = *(((unsigned char *) (&ip->ip)));
    return ((fbyte >= 0xE0) && (fbyte <= 0xEF));
}

inline bool issame_subnet(struct netaddr_ip *addr1, struct netaddr_ip *addr2, struct netaddr_ip *netmask) {
    return (addr1->ip & netmask->ip) == (addr2->ip & netmask->ip);
}

bool get_device_ipv4(char *iface_name, struct netaddr_ip *ip) {
    bool ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_addr.sa_family = AF_INET;

    ret = false;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFADDR, &req) >= 0) {
            ip->ip = ((struct sockaddr_in *) &req.ifr_addr)->sin_addr.s_addr;
            ret = true;
        }
        close(ctl_sock);
    }
    return ret;
}

bool get_device_netmask(char *iface_name, struct netaddr_ip *netmask) {
    bool ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_addr.sa_family = AF_INET;

    ret = false;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFNETMASK, &req) >= 0) {
            netmask->ip = ((struct sockaddr_in *) &req.ifr_addr)->sin_addr.s_addr;
            ret = true;
        }
        close(ctl_sock);
    }
    return ret;
}

bool parse_ipv4addr(char *ipstr, unsigned int *ip) {
    unsigned int ipaddr[IPV4ADDRSIZE];
    if (strlen(ipstr) >= IPV4STRLEN)
        return false;
    if (sscanf(ipstr, "%u.%u.%u.%u", ipaddr, ipaddr + 1, ipaddr + 2, ipaddr + 3) != 4)
        return false;
    if (ipaddr[0] > 255 || ipaddr[1] > 255 || ipaddr[2] > 255 || ipaddr[3] > 255)
        return false;
    if (ip != NULL)
        *ip = (ipaddr[3] << 24 | ipaddr[2] << 16 | ipaddr[1] << 8 | ipaddr[0]);
    return true;
}

char *get_stripv4(unsigned int *ip, bool _static) {
    static char static_buf[IPV4STRLEN];
    char *ipstr = static_buf;
    if (!_static) {
        if ((ipstr = (char *) malloc(IPV4STRLEN)) == NULL)
            return NULL;
    }
    return get_stripv4_r(ip, ipstr);
}

inline char *get_stripv4_r(unsigned int *ip, char *ipstr) {
    sprintf(ipstr, "%u.%u.%u.%u", (*ip) & 0xFF, (*ip) >> 8 & 0xFF, (*ip) >> 16 & 0xFF, (*ip) >> 24 & 0xFF);
    return ipstr;
}

struct Ipv4Header *build_ipv4_packet(struct netaddr_ip *src, struct netaddr_ip *dst, unsigned char ihl,
                                     unsigned short id, unsigned char ttl, unsigned char proto, unsigned short paysize,
                                     unsigned char *payload) {
    unsigned long size = IPV4HDRSIZE + paysize;
    struct Ipv4Header *ret = (struct Ipv4Header *) malloc(size);
    if (ret == NULL)
        return NULL;
    injects_ipv4_header((unsigned char *) ret, src, dst, ihl, id, paysize, ttl, proto);
    if (payload != NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

struct Ipv4Header *injects_ipv4_header(unsigned char *buf, struct netaddr_ip *src, struct netaddr_ip *dst,
                                       unsigned char ihl, unsigned short id, unsigned short len, unsigned char ttl,
                                       unsigned char proto) {
    struct Ipv4Header *ipv4 = (struct Ipv4Header *) buf;
    memset(ipv4, 0x00, IPV4HDRSIZE);
    ipv4->version = IPV4VERSION;
    ipv4->ihl = ihl;
    ipv4->len = htons((unsigned short) IPV4HDRSIZE + len);
    ipv4->id = id;
    ipv4->frag_off = htons(IPV4_FLAGS_DONTFRAG);
    ipv4->ttl = ttl;
    ipv4->protocol = proto;
    ipv4->saddr = src->ip;
    ipv4->daddr = dst->ip;
    ipv4->checksum = ipv4_checksum(ipv4);
    return ipv4;
}

unsigned short ipv4_checksum(struct Ipv4Header *ipHeader) {
    unsigned short *buf = (unsigned short *) ipHeader;
    ipHeader->checksum = 0;
    register unsigned int sum = 0;
    for (int i = 0; i < IPV4HDRSIZE; sum += *buf++, i += 2);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) ~sum;
}

inline unsigned short ipv4_mkid() {
    srand((unsigned int) clock());
    return ((uint16_t) rand());
}

inline void get_ipv4bcast_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *broadcast) {
    broadcast->ip = (~netmask->ip) | addr->ip;
}

inline void get_ipv4net_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *net) {
    net->ip = addr->ip & netmask->ip;
}

inline void get_ipv4wildcard_mask(struct netaddr_ip *netmask, struct netaddr_ip *ret_wildcard) {
    ret_wildcard->ip = ~netmask->ip;
}

void increment_ipv4addr(struct netaddr_ip *ip) {
    unsigned char *byte = (unsigned char *) &ip->ip;
    for (int i = IPV4ADDRSIZE - 1; i >= 0; i--)
        if (++byte[i] != 0x00)
            break;
}

void rndipv4(struct netaddr_ip *ip) {
    srand((unsigned int) clock());
    ip->ip = (unsigned int) rand();
}
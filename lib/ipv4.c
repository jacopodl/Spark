#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <time.h>
#include "ipv4.h"

bool parse_ipv4addr(char *ipstr, struct in_addr *ret_addr) {
    if (strlen(ipstr) >= IPV4STRSIZE)
        return false;
    unsigned int ipaddr[IPV4ADDRLEN];
    if (sscanf(ipstr, "%u.%u.%u.%u", ipaddr, ipaddr + 1, ipaddr + 2, ipaddr + 3) != 4)
        return false;
    if (ipaddr[0] > 255 || ipaddr[1] > 255 || ipaddr[2] > 255 || ipaddr[3] > 255)
        return false;
    if (ret_addr != NULL)
        ret_addr->s_addr = (ipaddr[3] << 24 | ipaddr[2] << 16 | ipaddr[1] << 8 | ipaddr[0]);
    return true;
}

char *get_stripv4(struct in_addr *addr) {
    char *ipstr = (char *) malloc(IPV4STRSIZE);
    if (ipstr == NULL)
        return NULL;
    sprintf(ipstr, "%u.%u.%u.%u", addr->s_addr & 0xFF, addr->s_addr >> 8 & 0xFF, addr->s_addr >> 16 & 0xFF,
            addr->s_addr >> 24 & 0xFF);
    return ipstr;
}

inline unsigned short build_id() {
    srand((unsigned int) time(NULL));
    return ((uint16_t) rand());
}

struct Ipv4Header *build_ipv4_packet(struct in_addr *src, struct in_addr *dst, unsigned char ihl, unsigned short len,
                                     unsigned short id, unsigned char ttl, unsigned char proto, unsigned long paysize,
                                     unsigned char *payload) {
    unsigned long size = sizeof(struct Ipv4Header) + paysize;
    struct Ipv4Header *ret = (struct Ipv4Header *) malloc(size);
    if (ret == NULL)
        return NULL;
    memset(ret, 0x00, size);
    ret->version = IPV4VERSION;
    ret->ihl = ihl;
    ret->len = htons(len);
    ret->id = id;
    ret->ttl = ttl;
    ret->protocol = proto;
    ret->saddr = src->s_addr;
    ret->daddr = dst->s_addr;
    memcpy(ret->data, payload, paysize);
    ipv4_checksum(ret);
    return ret;
}

inline void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr) {
    ret_addr->s_addr = (~netmask->s_addr) | addr->s_addr;
}

inline void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr) {
    ret_addr->s_addr = addr->s_addr & netmask->s_addr;
}

inline void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard) {
    ret_wildcard->s_addr = ~netmask->s_addr;
}

void increment_ipv4addr(struct in_addr *addr) {
    unsigned char *byte = (unsigned char *) &addr->s_addr;
    for (int i = IPV4ADDRLEN - 1; i >= 0; i--)
        if (++byte[i] != 0x00)
            break;
}

void injects_ipv4_header(unsigned char *buff, struct in_addr *src, struct in_addr *dst, unsigned char ihl,
                        unsigned short len, unsigned short id, unsigned char ttl, unsigned char proto) {
    struct Ipv4Header *ipv4 = (struct Ipv4Header *) buff;
    memset(ipv4, 0x00, sizeof(struct Ipv4Header));
    ipv4->version = IPV4VERSION;
    ipv4->ihl = ihl;
    ipv4->len = htons(len);
    ipv4->id = id;
    ipv4->ttl = ttl;
    ipv4->protocol = proto;
    ipv4->saddr = src->s_addr;
    ipv4->daddr = dst->s_addr;
    ipv4_checksum(ipv4);
}

void ipv4_checksum(struct Ipv4Header *ipHeader) {
    ipHeader->checksum = 0x00;
    unsigned short int *buff = (unsigned short int *) ipHeader;
    unsigned long sum = 0;
    for (int i = 0; i < sizeof(struct Ipv4Header); sum += buff[i], i++);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ipHeader->checksum = (unsigned short int) ~sum;
}

void rndipv4addr(struct in_addr *addr) {
    FILE *urandom;
    urandom = fopen("/dev/urandom", "r");
    addr->s_addr = 0;
    /*
    unsigned char byte;
    for (int i = 0; i < IPV4ADDRLEN; i++) {
        fread(&byte, 1, 1, urandom);
        addr->s_addr |= byte << (8 * i);
    }*/
    fread(&addr->s_addr, 4, 1, urandom);
    fclose(urandom);
}
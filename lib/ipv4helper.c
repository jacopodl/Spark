#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "ipv4helper.h"

bool parse_ipv4addr(char *ipstr, struct in_addr *ret_addr)
{
    if (strlen(ipstr) >= IPV4STRSIZ)
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

char *get_stripv4(struct in_addr *addr)
{
    char *ipstr = (char *) malloc(IPV4STRSIZ);
    if (ipstr == NULL)
        return NULL;
    sprintf(ipstr, "%u.%u.%u.%u", addr->s_addr & 0xFF, addr->s_addr >> 8 & 0xFF, addr->s_addr >> 16 & 0xFF,
            addr->s_addr >> 24 & 0xFF);
    return ipstr;
}

inline void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr)
{
    ret_addr->s_addr = (~netmask->s_addr) | addr->s_addr;
}

inline void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr)
{
    ret_addr->s_addr = addr->s_addr & netmask->s_addr;
}

inline void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard)
{
    ret_wildcard->s_addr = ~netmask->s_addr;
}

void increment_ipv4addr(struct in_addr *addr)
{
    unsigned char *byte = (unsigned char *) &addr->s_addr;
    for (int i = IPV4ADDRLEN - 1; i >= 0; i--)
        if (++byte[i] != 0x00)
            break;
}

void ipv4_checksum(struct ipv4_header *ipHeader)
{
    ipHeader->checksum=0x00;
    unsigned short int *buff = (unsigned short int*)ipHeader;
    unsigned long sum = 0;
    for(int i=0; i<sizeof(struct ipv4_header); sum+=buff[i],i++);
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    ipHeader->checksum= (unsigned short int)~sum;
}

void rndipv4addr(struct in_addr *addr)
{
    FILE *urandom;
    urandom = fopen("/dev/urandom", "r");
    addr->s_addr = 0;
    /*
    unsigned char byte;
    for (int i = 0; i < IPV4ADDRLEN; i++) {
        fread(&byte, 1, 1, urandom);
        addr->s_addr |= byte << (8 * i);
    }*/
    fread(&addr->s_addr,4,1,urandom);
    fclose(urandom);
}
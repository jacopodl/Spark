#ifndef IPV4HELPER
#define IPV4HELPER

#include <stdbool.h>
#include <arpa/inet.h>

#define IPV4HDRSIZE 20 /* Header size */
#define IPV4VERSION 4
#define IPV4MAXSIZE 65535
#define IPV4MAXTTL  255
#define IPV4DEFTTL  64

#define IPV4ADDRLEN 4
#define IPV4STRSIZ 16

struct ipv4_header
{
#if __BYTE_ORDER==__LITTLE_ENDIAN
    unsigned char ihl:4;
    unsigned char version :4;
    /* TOS */
    unsigned char ecn:2; /* Explicit Congestion Notification */
    unsigned char dscp:6; /* Differentiated Services Code Point */
    /* END TOS */
#elif __BYTE_ORDER==__BIG_ENDIAN
    unsigned char version :4;
    unsigned char ihl:4;
    /* TOS */
    unsigned char dscp:6; /* Differentiated Services Code Point */
    unsigned char ecn:2; /* Explicit Congestion Notification */
    /* END TOS */
#endif
    unsigned int len:16;
    unsigned int id:16;
#if __BYTE_ORDER==__LITTLE_ENDIAN
    unsigned int frag_off:13;
    unsigned char flags:3;
#elif __BYTE_ORDER==__BIG_ENDIAN
    unsigned char flags:3;
    unsigned int frag_off:13;
#endif
    unsigned char ttl;
    unsigned char protocol;
    unsigned int checksum:16;
    unsigned int saddr;
    unsigned int daddr;
};

bool parse_ipv4addr(char *ipstr, struct in_addr *ret_addr);

char *get_stripv4(struct in_addr *addr);

void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard);

void increment_ipv4addr(struct in_addr *addr);

void ipv4_checksum(struct ipv4_header *ipHeader);

void rndipv4addr(struct in_addr *addr);

#endif

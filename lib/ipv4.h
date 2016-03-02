#ifndef IPV4
#define IPV4

#include <stdbool.h>
#include <arpa/inet.h>

#define IPV4HDRSIZE 20      /* Header size */
#define IPV4VERSION 4       /* IP version  */
#define IPV4MAXSIZE 65535   /* IP max size */
#define IPV4MAXTTL  255     /* Time to live max value */
#define IPV4DEFTTL  64      /* Time to live default value */

#define IPV4ADDRLEN 4       /* IP addr length */
#define IPV4STRSIZE 16      /* IPV4 string size */

struct Ipv4Header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl:4;
    unsigned char version :4;
    /* TOS */
    unsigned char ecn:2;
    /* Explicit Congestion Notification */
    unsigned char dscp:6;   /* Differentiated Services Code Point */
    /* END TOS */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char version :4;
    unsigned char ihl:4;
    /* TOS */
    unsigned char dscp:6; /* Differentiated Services Code Point */
    unsigned char ecn:2; /* Explicit Congestion Notification */
    /* END TOS */
#endif
    unsigned int len:16;
    unsigned int id:16;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int frag_off:13;
    unsigned char flags:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char flags:3;
    unsigned int frag_off:13;
#endif
    unsigned char ttl;
    unsigned char protocol;
    unsigned int checksum:16;
    unsigned int saddr;
    unsigned int daddr;
    unsigned char data[0];
};

bool parse_ipv4addr(char *ipstr, struct in_addr *ret_addr);

char *get_stripv4(struct in_addr *addr);

unsigned short build_id();

struct Ipv4Header *build_ipv4_packet(struct in_addr *src, struct in_addr *dst, unsigned char ihl, unsigned short len,
                                     unsigned short id, unsigned char ttl, unsigned char proto, unsigned long paysize,
                                     unsigned char *payload);

void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard);

void increment_ipv4addr(struct in_addr *addr);

void injects_ipv4_header(unsigned char *buff, struct in_addr *src, struct in_addr *dst, unsigned char ihl,
                        unsigned short len, unsigned short id, unsigned char ttl, unsigned char proto);

void ipv4_checksum(struct Ipv4Header *ipHeader);

void rndipv4addr(struct in_addr *addr);

#endif

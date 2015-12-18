#ifndef IPV4HELPER
#define IPV4HELPER

#include <stdbool.h>
#include <arpa/inet.h>

#define IPV4ADDRLEN 4
#define IPV4STRSIZ 16

bool parse_ipv4addr(char *ipstr, struct in_addr *ret_addr);

char *get_stripv4(struct in_addr *addr);

void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard);

void increment_ipv4addr(struct in_addr *addr);

void rndipv4addr(struct in_addr *addr);

#endif

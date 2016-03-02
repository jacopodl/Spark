//
// Created by jdl on 24/02/16.
//

#ifndef ETHERNET
#define ETHERNET

#include <stdbool.h>
#include <net/if.h>

#define MACSTRSIZE  18      /* Mac addr string size */
#define ETHHDRSIZE  14      /* Ethernet header size */
#define ETHMAXPAYL  1500    /* Ethernet max payload */

struct EthHeader {
    unsigned char dhwaddr[IFHWADDRLEN];
    unsigned char shwaddr[IFHWADDRLEN];
    unsigned int  eth_type:16;
    unsigned char data[0];
};

struct EthHeader *build_ethernet_packet(struct sockaddr *src, struct sockaddr *dst, unsigned short type, unsigned long paysize, unsigned char *payload);

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr, bool bcast);

char *get_strhwaddr(struct sockaddr *hwa);

void injects_ethernet_header(unsigned char *buff, struct sockaddr *src, struct sockaddr *dst, unsigned short type);

void rndhwaddr(struct sockaddr *mac);

#endif

//
// Created by jdl on 24/02/16.
//

#ifndef ETHERNET
#define ETHERNET

#include <stdbool.h>
#include <net/if.h>

#define ETHHWASIZE  6       /* Ethernet addr byte len */
#define MACSTRSIZE  18      /* Mac addr string size */
#define ETHHDRSIZE  14      /* Ethernet header size */
#define ETHMINPAYL  64      /* Ethernet min payload */
#define ETHMAXPAYL  1500    /* Ethernet max payload */

#define ETHTYPE_PUP     0X0200
#define ETHTYPE_IP      0x0800
#define ETHTYPE_ARP     0X0806
#define ETHTYPE_RARP    0X8035

struct EthHeader {
    unsigned char   dhwaddr[ETHHWASIZE];
    unsigned char   shwaddr[ETHHWASIZE];
    unsigned short  eth_type;
    unsigned char   data[0];
};

struct EthHeader *build_ethernet_packet(struct sockaddr *src, struct sockaddr *dst, unsigned short type, unsigned long paysize, unsigned char *payload);

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr, bool bcast);

char *get_strhwaddr(struct sockaddr *hwa);

void injects_ethernet_header(unsigned char *buff, struct sockaddr *src, struct sockaddr *dst, unsigned short type);

void build_ethmulti_addr(struct sockaddr *hw, struct in_addr *ip);

void rndhwaddr(struct sockaddr *mac);

#endif

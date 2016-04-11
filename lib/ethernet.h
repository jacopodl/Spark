/*
* <ethernet, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SPARK_ETHERNET_H
#define SPARK_ETHERNET_H

#include <stdbool.h>
#include <netinet/in.h>

#define ETHHWASIZE      6       // Ethernet addr byte len
#define MACSTRSIZE      18      // Mac addr string size
#define MACSTRHLFSIZE   9       // Mac addr string half size
#define ETHHDRSIZE      14      // Ethernet header size
#define ETHMINPAYL      64      // Ethernet min payload
#define ETHMAXPAYL      1500    // Ethernet max payload

#define ETHTYPE_PUP     0X0200
#define ETHTYPE_IP      0x0800
#define ETHTYPE_ARP     0X0806
#define ETHTYPE_RARP    0X8035

struct EthHeader {
    unsigned char dhwaddr[ETHHWASIZE];
    unsigned char shwaddr[ETHHWASIZE];
    unsigned short eth_type;
    unsigned char data[0];
};

bool ethcmp(struct sockaddr *mac1, struct sockaddr *mac2);

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr, bool bcast);

char *get_strhwaddr(struct sockaddr *hwa, bool _static);

char *get_serial(struct sockaddr *hwa, bool _static);

char *get_vendor(struct sockaddr *hwa, bool _static);

struct EthHeader *build_ethernet_packet(struct sockaddr *src, struct sockaddr *dst, unsigned short type,
                                        unsigned long paysize, unsigned char *payload);

struct EthHeader *injects_ethernet_header(unsigned char *buff, struct sockaddr *src, struct sockaddr *dst,
                                          unsigned short type);

void build_ethbroad_addr(struct sockaddr *addr);

void build_ethmulti_addr(struct sockaddr *hw, struct in_addr *ip);

void rndhwaddr(struct sockaddr *mac);

#endif

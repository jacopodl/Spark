/*
* <ipv4, part of Spark.>
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

#ifndef IPV4
#define IPV4

#include <stdbool.h>
#include <arpa/inet.h>

#define IPV4VERSION 4                   // IP version
#define IPV4HDRSIZE 20                  // Header size
#define IPV4DEFTTL  64                  // Time to live default value
#define IPV4MAXTTL  255                 // Time to live max value
#define IPV4MINSIZE (IPV4HDRSIZE + 0)   // IPv4 min size
#define IPV4MAXSIZE 65535               // IPv4 max size

#define IPV4ADDRLEN 4                   // IP addr length
#define IPV4STRLEN  16                  // IPV4 string length

struct Ipv4Header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl:4;
    unsigned char version :4;
    /* TOS */
    unsigned char ecn:2;    // Explicit Congestion Notification
    unsigned char dscp:6;   // Differentiated Services Code Point
    /* END TOS */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char version :4;
    unsigned char ihl:4;
    /* TOS */
    unsigned char dscp:6;   // Differentiated Services Code Point
    unsigned char ecn:2;    // Explicit Congestion Notification
    /* END TOS */
#endif
    unsigned short len;
    unsigned short id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int frag_off:13;
    unsigned char flags:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char flags:3;
    unsigned int frag_off:13;
#endif
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int saddr;
    unsigned int daddr;
    unsigned char data[0];
};

bool parse_ipv4addr(char *ipstr, unsigned int *ret_addr);

char *get_stripv4(unsigned int *addr, bool _static);

struct Ipv4Header *build_ipv4_packet(struct in_addr *src, struct in_addr *dst, unsigned char ihl, unsigned short len,
                                     unsigned short id, unsigned char ttl, unsigned char proto, unsigned long paysize,
                                     unsigned char *payload);

struct Ipv4Header *injects_ipv4_header(unsigned char *buff, struct in_addr *src, struct in_addr *dst, unsigned char ihl,
                                       unsigned short len, unsigned short id, unsigned char ttl, unsigned char proto);

unsigned short build_ipv4id();

unsigned short ipv4_checksum(struct Ipv4Header *ipHeader);

void get_ipv4bcast_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4net_addr(struct in_addr *addr, struct in_addr *netmask, struct in_addr *ret_addr);

void get_ipv4wildcard_mask(struct in_addr *netmask, struct in_addr *ret_wildcard);

void increment_ipv4addr(struct in_addr *addr);

void rndipv4addr(struct in_addr *addr);

#endif

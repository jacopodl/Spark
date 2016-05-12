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

/**
 * @file ipv4.h
 * @brief Provides useful functions for build IPv4 packet and manage related addresses.
 */

#ifndef SPARK_IPV4_H
#define SPARK_IPV4_H

#include <stdbool.h>
#include <arpa/inet.h>
#include "datatype.h"

#define IPV4VERSION 4                   // IP version
#define IPV4HDRSIZE 20                  // Header size
#define IPV4DEFTTL  64                  // Time to live default value
#define IPV4MAXTTL  255                 // Time to live max value
#define IPV4MINSIZE (IPV4HDRSIZE + 0)   // IPv4 min size
#define IPV4MAXSIZE 65535               // IPv4 max size

#define IPV4ADDRLEN 4                   // IP addr length
#define IPV4STRLEN  16                  // IPV4 string length

/// @brief This structure rappresents an IPv4 packet.
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
    unsigned char data[];
};

/**
 * @brief Parse string contains a ipv4 address in the form `000.000.000.000`.
 * @param ipstr String contains ipv4 address in the form `000.000.000.000`.
 * @param __OUT__ret_addr Pointer to netaddr_ip structure.
 * @return Function returns true if the address has been converted, false otherwise.
 */
bool parse_ipv4addr(char *ipstr, unsigned int *ret_addr);

/**
 * @brief Obtains ipv4 address in the form `000.000.000.000`.
 * @param __IN__addr Pointer to netaddr_ip structure contains ip address.
 * @param _static Not allocate new memory, the result will be saved in a static buffer.
 * @return Function returns string contains ip address.
 */
char *get_stripv4(unsigned int *addr, bool _static);

/**
 * @brief Built a new IPv4 packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new IPv4 packet.
 * @param __IN__src Pointer to netaddr_ip structure contains source ip address.
 * @param __IN__dst Pointer to netaddr_ip structure contains destination ip address.
 * @param ihl Specifies the size of the header.
 * @param id Packet identifier.
 * @param ttl Time to live.
 * @param proto Type of the protocol in the payload field.
 * @param paysize Lenght of paylod.
 * @param __IN__payload IPv4 payload.
 * @return On success returns the pointer to new IPv4 packet of size equal to paysize + IPV4HDRSIZE, otherwise return NULL.
 */
struct Ipv4Header *build_ipv4_packet(struct netaddr_ip *src, struct netaddr_ip *dst, unsigned char ihl,
                                     unsigned short id, unsigned char ttl, unsigned char proto, unsigned short paysize,
                                     unsigned char *payload);

/**
 * @brief Injects IPv4 header into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param __IN__src Pointer to netaddr_ip structure contains source ip address.
 * @param __IN__dst Pointer to netaddr_ip structure contains destination ip address.
 * @param ihl Specifies the size of the header.
 * @param len Length of payload.
 * @param id Packet identifier.
 * @param ttl Time to live.
 * @param proto Type of the protocol in the payload field.
 * @return The function returns the pointer to IPv4 packet.
 */
struct Ipv4Header *injects_ipv4_header(unsigned char *buff, struct netaddr_ip *src, struct netaddr_ip *dst,
                                       unsigned char ihl,
                                       unsigned short len, unsigned short id, unsigned char ttl, unsigned char proto);

/**
 * @brief Builds a random ID.
 * @return The function returns a random ID.
 */
unsigned short build_ipv4id();

/**
 * @brief Computes the IPv4 checksum.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short ipv4_checksum(struct Ipv4Header *ipHeader);

/**
 * @brief Obtains broadcast IPv4 address.
 * @brief __IN__addr Pointer to netaddr_ip structure contains ip address.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__ret_addr Pointer to netaddr_ip structure.
 */
void get_ipv4bcast_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *ret_addr);

/**
 * @brief Obtains network address.
 * @brief __IN__addr Pointer to netaddr_ip structure contains ip address.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__ret_addr Pointer to netaddr_ip structure.
 */
void get_ipv4net_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *ret_addr);

/**
 * @brief Obtains wildcard mask.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__ret_wildcard Pointer to netaddr_ip structure.
 */
void get_ipv4wildcard_mask(struct netaddr_ip *netmask, struct netaddr_ip *ret_wildcard);

/**
 * @brief Obtains the next IPv4 address.
 * @brief __IN__OUT__addr Pointer to netaddr_ip structure contains the ip address.
 */
void increment_ipv4addr(struct netaddr_ip *addr);

/**
 * @brief Obtains a random IPv4 address.
 * @param __OUT__addr Pointer to netaddr_ip structure.
 */
void rndipv4addr(struct netaddr_ip *addr);

#endif

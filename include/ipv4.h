/*
 * Copyright (c) 2016-2017 Jacopo De Luca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
#define IPV4DEFIHL  5                   // Default IHL value
#define IPV4MAXTTL  255                 // Time to live max value
#define IPV4MINSIZE (IPV4HDRSIZE + 0)   // IPv4 min size
#define IPV4MAXSIZE 65535               // IPv4 max size

#define IPV4ADDRSIZE    4                   // IP address length
#define IPV4STRLEN      16                  // IPV4 string length

/// @brief This structure represents an IPv4 packet.
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
#define IPV4_FLAGS_DONTFRAG 0x4000
#define IPV4_FLAGS_MOREFRAG 0x2000
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int saddr;
    unsigned int daddr;
    unsigned char data[];
};

/**
 * @brief Compare two IPv4 address.
 * @param ip1 Pointer to netaddr_ip structure contains first ip address.
 * @param ip2 Pointer to netaddr_ip structure contains seconds ip address.
 * @return Function returns true if ip1 is equals to ip2, false otherwise.
 */
bool ipv4cmp(struct netaddr_ip *ip1, struct netaddr_ip *ip2);

/**
 * @brief Checks if is a broadcast(255.255.255.255) IPv4 address.
 * @param ip Pointer to netaddr_ip structure contains ip address.
 * @return Function returns true if is a broadcast address, false otherwise.
 */
bool isbcast_ipv4(struct netaddr_ip *ip);

/**
 * @brief Checks if is a broadcast IPv4 address.
 * @param ip Pointer to netaddr_ip structure contains ip address.
 * @param netmask Pointer to netaddr_ip structure contains netmask address.
 * @return Function returns true if is a broadcast address, false otherwise.
 */
bool isbcast2_ipv4(struct netaddr_ip *ip, struct netaddr_ip *netmask);

/**
 * @brief Checks if is a empty IPv4 address (All byte are zero!).
 * @param ip Pointer to netaddr_ip structure contains ip address.
 * @return Function returns true if is empty IPv4 address, false otherwise.
 */
bool isempty_ipv4(struct netaddr_ip *ip);

/**
 * @brief Checks if is a multicast(class D) IPv4 address.
 * @param ip Pointer to netaddr_ip structure contains ip address.
 * @return Function returns true if is a class D address, false otherwise.
 */
bool ismcast_ipv4(struct netaddr_ip *ip);

/**
 * @brief Check if they are addresses on the same subnet.
 * @param addr1 Pointer to netaddr_ip structure contains first ip address.
 * @param addr2 Pointer to netaddr_ip structure contains seconds ip address.
 * @param netmask Pointer to netaddr_ip structure contains netmask.
 * @return Function returns true if the addr1 and addr2 are on the same subnet, false otherwise.
 */
bool issame_subnet(struct netaddr_ip *addr1, struct netaddr_ip *addr2, struct netaddr_ip *netmask);

/**
 * @brief Obtains the IPv4 address of device called `iface_name`.
 * @param iface_name Interface name.
 * @param __OUT__ip Pointer to netaddr_ip structure.
 * @return Function returns true if the address has been obtained, false otherwise.
 */
bool get_device_ipv4(char *iface_name, struct netaddr_ip *ip);

/**
 * @brief Obtains the IPv4 netmask of device called `iface_name`.
 * @param iface_name Interface name.
 * @param __OUT__netmask Pointer to netaddr_ip structure.
 * @return Function returns true if the netmask has been obtained, false otherwise.
 */
bool get_device_netmask(char *iface_name, struct netaddr_ip *netmask);

#ifdef USE_DEPRECATED

/**
 * @brief Parse string contains a ipv4 address in the form `000.000.000.000`.
 * @param ipstr String contains ipv4 address in the form `000.000.000.000`.
 * @param __OUT__ip Pointer to int(32bit).
 * @return Function returns true if the address has been converted, false otherwise.
 */
bool parse_ipv4addr(char *ipstr, unsigned int *ip) __attribute__((deprecated));

/**
 * @brief Obtains ipv4 address in the form `000.000.000.000`.
 * @param __IN__ip Pointer to integer(32bit) contains IPv4.
 * @param _static Not allocate new memory, the result will be saved in internal static bufer.
 * @return Function returns string contains ip address.
 */
char *get_stripv4(unsigned int *ip, bool _static) __attribute__((deprecated));

/**
 * @brief Obtains ipv4 address in the form `000.000.000.000`.
 * @param __IN__ip Pointer to integer(32bit) contains IPv4.
 * @param __OUT__ipstr Pointer to string of dimension IPV4STRLEN.
 * @return Function returns string contains ip address.
 */
char *get_stripv4_r(unsigned int *ip, char *ipstr) __attribute__((deprecated));

#else

/**
 * @brief Parse string contains a ipv4 address in the form `000.000.000.000`.
 * @param ipstr String contains ipv4 address in the form `000.000.000.000`.
 * @param __OUT__ip Pointer to netaddr_ip structure.
 * @return Function returns true if the address has been converted, false otherwise.
 */
bool parse_ipv4addr(char *ipstr, struct netaddr_ip *ip);

/**
 * @brief Obtains ipv4 address in the form `000.000.000.000`.
 * @param __IN__ip Pointer to netaddr_ip structure.
 * @param _static Not allocate new memory, the result will be saved in internal static bufer.
 * @return Function returns string contains ip address.
 */
char *get_stripv4(struct netaddr_ip *ip, bool _static);

/**
 * @brief Obtains ipv4 address in the form `000.000.000.000`.
 * @param __IN__ip Pointer to netaddr_ip structure.
 * @param __OUT__ipstr Pointer to string of dimension IPV4STRLEN.
 * @return Function returns string contains ip address.
 */
char *get_stripv4_r(struct netaddr_ip *ip, char *ipstr);

#endif

/**
 * @brief Built a new IPv4 packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload bufer in the new IPv4 packet.
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
 * @brief Injects IPv4 header into a bufer pointed by `buf`.
 * @param __OUT__buf Pointer to remote bufer.
 * @param __IN__src Pointer to netaddr_ip structure contains source ip address.
 * @param __IN__dst Pointer to netaddr_ip structure contains destination ip address.
 * @param ihl Specifies the size of the header.
 * @param id Packet identifier.
 * @param len Length of payload.
 * @param ttl Time to live.
 * @param proto Type of the protocol in the payload field.
 * @return The function returns the pointer to IPv4 packet.
 */
struct Ipv4Header *injects_ipv4_header(unsigned char *buf, struct netaddr_ip *src, struct netaddr_ip *dst,
                                       unsigned char ihl, unsigned short id, unsigned short len, unsigned char ttl,
                                       unsigned char proto);

/**
 * @brief Computes the IPv4 checksum.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short ipv4_checksum(struct Ipv4Header *ipHeader);

/**
 * @brief Builds a random ID.
 * @return The function returns a random ID.
 */
unsigned short ipv4_mkid();

/**
 * @brief Obtains broadcast IPv4 address.
 * @brief __IN__addr Pointer to netaddr_ip structure contains ip address.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__broadcast Pointer to netaddr_ip structure.
 */
void get_ipv4bcast_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *broadcast);

/**
 * @brief Obtains network address.
 * @brief __IN__addr Pointer to netaddr_ip structure contains ip address.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__net Pointer to netaddr_ip structure.
 */
void get_ipv4net_addr(struct netaddr_ip *addr, struct netaddr_ip *netmask, struct netaddr_ip *net);

/**
 * @brief Obtains wildcard mask.
 * @brief __IN__netmask Pointer to netaddr_ip structure contains the subnet mask.
 * @param __OUT__ret_wildcard Pointer to netaddr_ip structure.
 */
void get_ipv4wildcard_mask(struct netaddr_ip *netmask, struct netaddr_ip *ret_wildcard);

/**
 * @brief Obtains the next IPv4 address.
 * @brief __IN__OUT__ip Pointer to netaddr_ip structure contains the ip address.
 */
void increment_ipv4addr(struct netaddr_ip *ip);

/**
 * @brief Obtains a random IPv4 address.
 * @param __OUT__ip Pointer to netaddr_ip structure.
 */
void rndipv4(struct netaddr_ip *ip);

#endif

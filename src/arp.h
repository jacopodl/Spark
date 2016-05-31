/*
* <arp, part of Spark.>
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
 * @file arp.h
 * @brief Provides useful functions for build and manage ARP packets, also contains a micro implementation of ARP resolver.
 */

#ifndef SPARK_ARP_H
#define SPARK_ARP_H

#include "datatype.h"
#include "netdevice.h"
#include "ethernet.h"
#include "ipv4.h"

#define ARPHWT_ETH      1
#define ARPHWT_EXPETH   2
#define ARPHWT_AX25     3
#define ARPHWT_PRONET   4
#define ARPHWT_CHAOS    5
#define ARPHWT_ARCNET   7
#define ARPHWT_FRAMER   15
#define ARPHWT_ATM      16
#define ARPHWT_HDLC     17
#define ARPHWT_FIBRE    18
#define ARPHWT_ARPSEC   30
#define ARPHWT_IPSECT   31
#define ARPHWT_INFINIB  32

#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
#define ARPOP_REVREQ    3
#define ARPOP_REVREP    4

#define ARPHDRSIZE          8
#define ARPETHIPLEN    (ARPHDRSIZE + ((ETHHWASIZE+IPV4ADDRLEN)*2))

#define ARPRESOLVER_ATTEMPTS       3
#define ARPRESOLVER_PACKETS        50
#define ARPRESOLVER_TIMEOUT_SEC    1
#define ARPRESOLVER_TIMEOUT_USEC   (200 * 1000)

/// @brief This structure rapresents an ARP packet.
struct ArpPacket {
    /// @brif Hardware type.
    unsigned short hw_type;
    /// @brif Specifies the internetwork protocol Eg: IPv4.
    unsigned short proto;
    /// @brif Length of a hardware address.
    unsigned char hwalen;
    /// @brif Length of addresses used in the upper layer protocol.
    unsigned char pralen;
    /// @brief Specifies the operation that the sender is performing.
    unsigned short opcode;
    /// @brief Sender hardware address + Sender protocol address + Target hardware address + Target protocol address.
    unsigned char data[];
};

/**
 * @brief Built a new generic ARP packet.
 * @param hwlen Length of a hardware address.
 * @param pralen Length of addresses used in the upper layer protocol.
 * @param opcode Specifies the operation that the sender is performing.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return On success returns the pointer to new generic ARP packet, otherwise return NULL.
 */
struct ArpPacket *build_arp_packet(unsigned char hwalen, unsigned char pralen, unsigned short opcode,
                                   struct netaddr *shwaddr, struct netaddr *spraddr, struct netaddr *dhwaddr,
                                   struct netaddr *dpraddr);

/**
 * @brief Injects generic ARP packet into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param hwlen Length of a hardware address.
 * @param pralen Length of addresses used in the upper layer protocol.
 * @param opcode Specifies the operation that the sender is performing.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to generic ARP packet.
 */
struct ArpPacket *injects_arp_packet(unsigned char *buff, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct netaddr *shwaddr, struct netaddr *spraddr,
                                     struct netaddr *dhwaddr, struct netaddr *dpraddr);

/**
 * @brief Injects ARP replay packet into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to ARP replay packet.
 */
struct ArpPacket *injects_arp_reply(unsigned char *buff, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                    struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr);

/**
 * @brief Injects ARP request packet into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to ARP request packet.
 */
struct ArpPacket *injects_arp_request(unsigned char *buff, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                      struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr);

/**
 * @brief Obtains MAC address of remote device.
 * @param __IN__llo Pointer to llOptions structure which handles the active raw socket.
 * @param __IN__shwaddr Sender mac address.
 * @param __IN__spraddr Sender ip address.
 * @param __OUT__dhwaddr Target mac address.
 * @param __IN__dpraddr Set target ip address.
 * @return The function returns 1 if the ARP request was successful, otherwise, 0 is  returned.
 * On error -1 is returned and errno set to indicate the error.
 */
int arp_resolver(struct llOptions *llo, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                 struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr);

#endif

/*
 * Copyright (c) 2016 - 2017 Jacopo De Luca
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
 * @file arp.h
 * @brief Provides useful functions for build and manage ARP packets.
 */

#ifndef SPARK_ARP_H
#define SPARK_ARP_H

#include "datatype.h"
#include "netdevice.h"
#include "ethernet.h"
#include "ip.h"

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

#define ARPHDRSIZE      8
#define ARPETHIPSIZE    (ARPHDRSIZE + ((ETHHWASIZE+IPADDRSIZE)*2))

/// @brief This structure represents an ARP packet.
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
}__attribute__((packed));

/**
 * @brief Built a new generic ARP packet.
 * @param hw_type Hardware type.
 * @param proto Protocol type.
 * @param hwlen Length of a hardware address.
 * @param pralen Length of addresses used in the upper layer protocol.
 * @param opcode Specifies the operation that the sender is performing.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return On success returns the pointer to new generic ARP packet, otherwise return NULL.
 */
struct ArpPacket *arp_build_packet(unsigned short hw_type, unsigned short proto, unsigned char hwalen,
                                   unsigned char pralen, unsigned short opcode, struct netaddr_generic *shwaddr,
                                   struct netaddr_generic *spraddr, struct netaddr_generic *dhwaddr,
                                   struct netaddr_generic *dpraddr);

/**
 * @brief Injects generic ARP packet into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote buffer.
 * @param hw_type Hardware type.
 * @param proto Protocol type.
 * @param hwlen Length of a hardware address.
 * @param pralen Length of addresses used in the upper layer protocol.
 * @param opcode Specifies the operation that the sender is performing.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to generic ARP packet.
 */
struct ArpPacket *arp_inject_packet(unsigned char *buf, unsigned short hw_type, unsigned short proto,
                                    unsigned char hwalen, unsigned char pralen, unsigned short opcode,
                                    struct netaddr_generic *shwaddr, struct netaddr_generic *spraddr,
                                    struct netaddr_generic *dhwaddr, struct netaddr_generic *dpraddr);

/**
 * @brief Injects ARP replay packet into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote buffer.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to ARP replay packet.
 */
struct ArpPacket *arp_inject_reply(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                   struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr);

/**
 * @brief Injects ARP request packet into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote buffer.
 * @param __IN__shwaddr Sender hardware address.
 * @param __IN__spraddr Sender protocol address.
 * @param __IN__dhwaddr Target hardware address.
 * @param __IN__dpraddr Target protocol address.
 * @return The function returns the pointer to ARP request packet.
 */
struct ArpPacket *arp_inject_request(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                     struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr);

/**
 * @brief Obtains dest IP address from ArpPacket.
 * @param __IN__ap Pointer to ArpPacket.
 * @return The function returns netaddr_ip.
 */
struct netaddr_ip arp_getaddr_d(struct ArpPacket *ap);

/**
 * @brief Obtains src IP address from ArpPacket.
 * @param __IN__ap Pointer to ArpPacket.
 * @return The function returns netaddr_ip.
 */
struct netaddr_ip arp_getaddr_s(struct ArpPacket *ap);

/**
 * @brief Obtains dest MAC address from ArpPacket.
 * @param __IN__ap Pointer to ArpPacket.
 * @return The function returns netaddr_mac.
 */
struct netaddr_mac arp_gethwaddr_d(struct ArpPacket *ap);

/**
 * @brief Obtains src MAC address from ArpPacket.
 * @param __IN__ap Pointer to ArpPacket.
 * @return The function returns netaddr_mac.
 */
struct netaddr_mac arp_gethwaddr_s(struct ArpPacket *ap);

#endif

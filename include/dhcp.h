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
 * @file dhcp.h
 * @brief Provides functions for manage DHCP message.
 */

#ifndef SPARK_DHCP_H
#define SPARK_DHCP_H

#include "datatype.h"

/* Values for OP field */
#define DHCP_OP_BOOT_REQUEST    1
#define DHCP_OP_BOOT_REPLY      2

/* Values for HTYPE field */
#define DHCP_HTYPE_ETHER     1
#define DHCP_HTYPE_IEEE802   6
#define DHCP_HTYPE_FDDI      8

/* Value for flags field */
#define DHCP_FLAGS_BROADCAST 0x8000

/* Values for option field */
/* FIRST OPTION MUST BE DHCP_MAGIC_COOKIE */
#define DHCP_MAGIC_COOKIE (0x63825363)   // Magic cookie validating DHCP options field (and bootp vendor extensions field)

#define DHCP_REQUESTED_ADDRESS      50
#define DHCP_ADDR_LEASE_TIME        51
#define DHCP_MESSAGE_TYPE           53
#define DHCP_SERVER_IDENTIFIER      54
#define DHCP_PARAMETER_REQUEST_LIST 55
#define DHCP_CLIENT_IDENTIFIER      61

/* Parameter request list */
#define DHCP_REQ_SUBMASK        1
#define DHCP_REQ_ROUTERS        3
#define DHCP_REQ_DNS            6
#define DHCP_REQ_DOMAIN_NAME    15
#define DHCP_NTP_SERVERS        42


/* DHCP message types */
#define DHCP_DISCOVER    1
#define DHCP_OFFER       2
#define DHCP_REQUEST     3
#define DHCP_DECLINE     4
#define DHCP_ACK         5
#define DHCP_NAK         6
#define DHCP_RELEASE     7
#define DHCP_INFORM      8

#define DHCPPKTSIZE     548
#define DHCP_CHADDRLEN  16
#define DHCP_SNAMELEN   64
#define DHCP_FILELEN    128
#define DHCP_OPTLEN     308

/// @brief This structure represents an DHCP message.
struct DhcpPacket {
    /// @brief opcode.
    unsigned char op;
    /// @brief Hardware type Eg: Ethernet.
    unsigned char htype;
    /// @brief Hardware address length.
    unsigned char hlen;
    /// @brief Hop count.
    unsigned char hops;
    /// @brief Transaction ID.
    unsigned int xid;
    /// @brief Number of seconds.
    unsigned short secs;
    /// @brief Flags
    unsigned short flags;
    /// @brief Client IP address.
    unsigned int ciaddr;
    /// @brief Your IP address.
    unsigned int yiaddr;
    /// @brief Server IP address.
    unsigned int siaddr;
    /// @brief Gateway IP address.
    unsigned int giaddr;
    /// @brief Client hardware address.
    unsigned char chaddr[DHCP_CHADDRLEN];
    /// @brief Server host name.
    unsigned char sname[DHCP_SNAMELEN];
    /// @brief Boot filename.
    unsigned char file[DHCP_FILELEN];
    /// @brief Contains always DHCP MAGIC COOKIE 0x63825363.
    unsigned int option;
    /// @brief Miscellaneous options.
    unsigned char options[DHCP_OPTLEN];
}__attribute__((packed));

/**
 * @brief Append the new option at the end of DHCP message.
 *
 * @param __OUT__dhcpPkt Pointer to remote DHCP packet.
 * @param op Option.
 * @param len Option length.
 * @param __IN__payload Option payload.
 * @return On success returns true, if there is not enough space at the end of the message, false is returned.
 */
bool dhcp_append_option(struct DhcpPacket *dhcpPkt, unsigned char op, unsigned char len, unsigned char *payload);

/**
 * @brief Checks the type of the DHCP message.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @param type Requested type.
 * @return If the requested type corresponds with the type of the DHCP message, this function returns true, otherwise false is returned.
 */
bool dhcp_type_equals(struct DhcpPacket *dhcpPkt, unsigned char type);

/**
 * @brief Obatins the uint value of DHCP option.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @param options DHCP option.
 * @return On success this function returns the value of the DHCP option, otherwise 0 is returned.
 */
unsigned int dhcp_get_option_uint(struct DhcpPacket *dhcpPkt, unsigned char option);

/**
 * @brief Built a new DHCP raw packet.
 *
 * @param op Opcode.
 * @param hops Number of hop.
 * @param xid Transaction ID.
 * @param secs Number of seconds.
 * @param flags Flags.
 * @param __IN__ciaddr Client IP address.
 * @param __IN__yiaddr Your IP address.
 * @param __IN__siaddr Server IP address.
 * @param __IN__giaddr Gateway IP address.
 * @param __IN__chaddr Client hardware address.
 * @param __IN__sname Server host name.
 * @return On success returns the pointer to new DHCP packet, otherwise return NULL.
 */
struct DhcpPacket *dhcp_build_raw(unsigned char op, unsigned char hops, unsigned int xid, unsigned short secs,
                                  unsigned short flags, struct netaddr_ip *ciaddr, struct netaddr_ip *yiaddr,
                                  struct netaddr_ip *siaddr, struct netaddr_ip *giaddr, struct netaddr_mac *chaddr,
                                  char *sname);

/**
 * @brief Injects DHCP discover message into a bufer pointed by `buf`.
 *
 * @param __OUT__buf Pointer to remote bufer.
 * @param __IN__chaddr Client hardware address.
 * @param __IN__ipreq Requested IP address, maybe NULL.
 * @param flags Flags.
 * @return The function returns the pointer to DHCP discover packet.
 */
struct DhcpPacket *dhcp_inject_discovery(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                         unsigned short flags);

/**
 * @brief Injects DHCP raw packet into a bufer pointed by `buf`.
 *
 * @param __OUT__buf Pointer to remote bufer.
 * @param op Opcode.
 * @param hops Number of hop.
 * @param xid Transaction ID.
 * @param secs Number of seconds.
 * @param flags Flags.
 * @param __IN__ciaddr Client IP address.
 * @param __IN__yiaddr Your IP address.
 * @param __IN__siaddr Server IP address.
 * @param __IN__giaddr Gateway IP address.
 * @param __IN__chaddr Client hardware address.
 * @param __IN__sname Server host name.
 * @return The function returns the pointer to DHCP packet.
 */
struct DhcpPacket *dhcp_inject_raw(unsigned char *buf, unsigned char op, unsigned char hops, unsigned int xid,
                                   unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                   struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                   struct netaddr_mac *chaddr, char *sname);

/**
 * @brief Injects DHCP release message into a bufer pointed by `buf`.
 *
 * @param __OUT__buf Pointer to remote bufer.
 * @param __IN__chaddr Client hardware address.
 * @param __IN__ciaddr Client IP address.
 * @param __IN__server DHCP server ip address.
 * @param flags Flags.
 * @return The function returns the pointer to DHCP release packet.
 */
struct DhcpPacket *dhcp_inject_release(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ciaddr,
                                       struct netaddr_ip *server, unsigned short flags);

/**
 * @brief Injects DHCP request message into a bufer pointed by `buf`.
 *
 * @param __OUT__buf Pointer to remote bufer.
 * @param __IN__chaddr Client hardware address.
 * @param __IN__ipreq Requested IP address.
 * @param xid Transaction ID.
 * @param __IN__siaddr DHCP server ip address.
 * @param flags Flags.
 * @return The function returns the pointer to DHCP request packet.
 */
struct DhcpPacket *dhcp_inject_request(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                       unsigned int xid, struct netaddr_ip *siaddr, unsigned short flags);

/**
 * @brief Obtains DHCP message type.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @return DHCP message type.
 */
unsigned char dhcp_get_type(struct DhcpPacket *dhcp);

/**
 * @brief Obatins options list.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @param __OUT__len Length of options list.
 * @return On success this function returns an array with all options contained in the DHCP message, otherwise NULL is returned.
 * @warning The returned array doesn't contains the null terminator!
 */
unsigned char *dhcp_get_options(struct DhcpPacket *dhcpPkt, unsigned int *len);

/**
 * @brief Obatins the uchar value of DHCP option.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @param options DHCP option.
 * @return On success this function returns the value of the DHCP option, otherwise 0 is returned.
 */
unsigned char dhcp_get_option_uchar(struct DhcpPacket *dhcpPkt, unsigned char option);

/**
 * @brief Obatins the value of DHCP option.
 *
 * @param __IN__dhcpPkt Pointer to remote DHCP packet.
 * @param options DHCP option.
 * @param __OUT__len Option length.
 * @return On success this function returns an array with the value of the DHCP option, otherwise NULL is returned.
 * @warning The returned array doesn't contains the null terminator!
 */
unsigned char *dhcp_get_option_value(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned int *len);

/**
 * @brief Obtains a random ID for DHCP message.
 * @return Random transaction ID.
 */
unsigned int dhcp_mkxid();

#endif

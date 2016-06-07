/*
* <dhcp, part of Spark.>
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
#define DHCP_MAGIC_COOKIE (0x63825363)   // Magic cookie validating dhcp options field (and bootp vendor extensions field)

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

#define DHCPPKTLEN      548
#define DHCP_CHADDRLEN  (16)
#define DHCP_SNAMELEN   (64)
#define DHCP_FILELEN    (128)
#define DHCP_OPTLEN     (308)

struct DhcpPacket {
    unsigned char op;
    unsigned char htype;
    unsigned char hlen;
    unsigned char hops;
    unsigned int xid;
    unsigned short secs;
    unsigned short flags;
    /* unused */
    unsigned int ciaddr;
    unsigned int yiaddr;
    unsigned int siaddr;
    unsigned int giaddr;
    unsigned char chaddr[DHCP_CHADDRLEN];
    unsigned char sname[DHCP_SNAMELEN];
    unsigned char file[DHCP_FILELEN];
    unsigned int option;
    /* MAGIC COOKIE */
    unsigned char options[DHCP_OPTLEN];
};

bool dhcp_append_option(struct DhcpPacket *dhcpPkt, unsigned char op, unsigned char len,
                        unsigned char *payload);

bool dhcp_check_type(struct DhcpPacket *dhcpPkt, unsigned char type);

bool dhcp_replace_option(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned char *value, unsigned char offset);

unsigned int dhcp_get_option_uint(struct DhcpPacket *dhcpPkt, unsigned char option);

struct DhcpPacket *build_dhcp_raw(unsigned char *buff, unsigned char op, unsigned char htype, unsigned char hlen,
                                  unsigned char hops, unsigned int xid,
                                  unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                  struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                  struct netaddr *chaddr, char *sname);

struct DhcpPacket *injects_dhcp_discover(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                         unsigned short flags);

struct DhcpPacket *injects_dhcp_raw(unsigned char *buff, unsigned char op, unsigned char htype, unsigned char hlen,
                                    unsigned char hops, unsigned int xid,
                                    unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                    struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                    struct netaddr *chaddr, char *sname);

struct DhcpPacket *injects_dhcp_release(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ciaddr,
                                        struct netaddr_ip *server, unsigned short flags);

struct DhcpPacket *injects_dhcp_request(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                        unsigned int xid, struct netaddr_ip *siaddr, unsigned short flags);

unsigned char dhcp_get_type(struct DhcpPacket *dhcp);

unsigned char *dhcp_get_options(struct DhcpPacket *dhcpPkt, unsigned int *len);

unsigned char dhcp_get_option_uchar(struct DhcpPacket *dhcpPkt, unsigned char option);

unsigned char *dhcp_get_option_value(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned int *len);

unsigned int dhcp_mkxid();

#endif

/*
* <icmp, part of Spark.>
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

#ifndef SPARK_ICMP
#define SPARK_ICMP

#define ICMPTY_ECHO_REPLY           0
#define ICMPTY_DST_UNREACHABLE      3
#define ICMPTY_SRCQUENCH            4
#define ICMPTY_REDIRECT             5
#define ICMPTY_ECHO_REQUEST         8
#define ICMPTY_ROUTER_ADVERTISMENT  9
#define ICMPTY_ROUTER_SOLICITATION  10
#define ICMPTY_TIME_EXCEEDED        11
#define ICMPTY_PARAMETER_PROBLEM    12
#define ICMPTY_TIMESTAMP_REQUEST    13
#define ICMPTY_TIMESTAMP_REPLY      14
#define ICMPTY_INFO_REQUEST         15  // Obsolete
#define ICMPTY_INFO_REPLY           16  // Obsolete
#define ICMPTY_ADDR_MASK_REQUEST    17
#define ICMPTY_ADDR_MASK_REPLY      18
#define ICMPTY_TRACEROUTE           30
#define ICMPTY_CONVERSION_ERROR     31
#define ICMPTY_DOMAIN_NAME_REQUEST  37
#define ICMPTY_DOMAIN_NAME_REPLY    38


#define ICMP4HDRSIZE    8

struct IcmpHeader {
    unsigned char type;
    unsigned char code;
    unsigned short chksum;
    union {
        struct {
            unsigned short id;
            unsigned short sqn;
        } echo;
        struct {
            unsigned short unused;
            unsigned short mtu;
        } mtu;
        unsigned int hdr;
    };
    unsigned char data[0];
};

struct IcmpHeader *build_icmp4_packet(unsigned char type, unsigned char code, struct Ipv4Header *ipv4Header,
                                      unsigned long paysize,
                                      unsigned char *payload);

struct IcmpHeader *build_icmp4_echo_request(unsigned char *buff, unsigned short id, unsigned short seqn,
                                            struct Ipv4Header *ipv4Header, unsigned long paysize,
                                            unsigned char *payload);

struct IcmpHeader *injects_icmp4_header(unsigned char *buff, unsigned char type, unsigned char code);

struct IcmpHeader *injects_icmp4_echo_request(unsigned char *buff, unsigned short id, unsigned short seqn,
                                              struct Ipv4Header *ipv4Header, unsigned long paysize,
                                              unsigned char *payload);

static struct IcmpHeader *buinj_icmp4_echo_request(unsigned char *buff, bool memalloc, unsigned short id,
                                                   unsigned short seqn,
                                                   struct Ipv4Header *ipv4Header, unsigned long paysize,
                                                   unsigned char *payload);

unsigned short icmp4_checksum(struct IcmpHeader *icmpHeader, struct Ipv4Header *ipv4Header);

#endif

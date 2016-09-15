/*
* icmp, part of Spark.
* Copyright (C) 2015-2016 Jacopo De Luca
*
* This program is free library: you can redistribute it and/or modify
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
 * @file icmp4.h
 * @brief Provides functions for build and manage ICMPv4 packets.
 */

#ifndef SPARK_ICMP_H
#define SPARK_ICMP_H

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

/// @brief This structure represents an IPv4 packet.
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
    unsigned char data[];
};

/**
 * @brief Built a new ICMP echo request packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new ICMP packet, otherwise the icmp packet will be filled with random data of size equals of paysize.
 * @param id Packet identifier.
 * @param seqn Packet sequence.
 * @param paysize Lenght of paylod.
 * @param __IN__payload ICMP payload.
 * @return On success returns the pointer to new ICMP packet of size equal to paysize + ICMP4HDRSIZE, otherwise return NULL.
 */
struct IcmpHeader *build_icmp4_echo_request(unsigned short id, unsigned short seqn, unsigned short paysize,
                                            unsigned char *payload);

/**
 * @brief Built a new ICMP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new ICMP packet.
 * @param type Message type.
 * @param code Message code.
 * @param paysize Lenght of paylod.
 * @param __IN__payload ICMP payload.
 * @return On success returns the pointer to new ICMP packet of size equal to paysize + ICMP4HDRSIZE, otherwise return NULL.
 */
struct IcmpHeader *build_icmp4_packet(unsigned char type, unsigned char code, unsigned short paysize,
                                      unsigned char *payload);

/**
 * @brief Injects ICMP header into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param id Packet identifier.
 * @param seqn Packet sequence.
 * @return The function returns the pointer to ICMP packet.
 */
struct IcmpHeader *injects_icmp4_echo_request(unsigned char *buff, unsigned short id, unsigned short seqn);

/**
 * @brief Injects ICMP header into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param type Message type.
 * @param code Message code.
 * @return The function returns the pointer to ICMP packet.
 */
struct IcmpHeader *injects_icmp4_header(unsigned char *buff, unsigned char type, unsigned char code);

/**
 * @brief Computes the ICMP checksum.
 * @param __IN__icmpHeader Pointer to remote ICMP packet.
 * @param paysize Size of ICMP payload.
 * @return The function returns the checksum.
 */
unsigned short icmp4_checksum(struct IcmpHeader *icmpHeader, unsigned short paysize);

#endif

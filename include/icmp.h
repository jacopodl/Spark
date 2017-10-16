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
 * @file icmp.h
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
}__attribute__((packed));

/**
 * @brief Built a new ICMP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload bufer in the new ICMP packet.
 * @param type Message type.
 * @param code Message code.
 * @param paysize Lenght of paylod.
 * @param __IN__payload ICMP payload.
 * @return On success returns the pointer to new ICMP packet of size equal to paysize + ICMP4HDRSIZE, otherwise return NULL.
 */
struct IcmpHeader *icmp_build_packet(unsigned char type, unsigned char code, unsigned short paysize,
                                     unsigned char *payload);

/**
 * @brief Injects ICMP echo reply into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote bufer.
 * @param id Packet identifier.
 * @param seqn Packet sequence.
 * @return The function returns the pointer to ICMP packet.
 */
struct IcmpHeader *icmp_inject_echo_reply(unsigned char *buf, unsigned short id, unsigned short seqn);

/**
 * @brief Injects ICMP echo request into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote bufer.
 * @param id Packet identifier.
 * @param seqn Packet sequence.
 * @return The function returns the pointer to ICMP packet.
 */
struct IcmpHeader *icmp_inject_echo_request(unsigned char *buf, unsigned short id, unsigned short seqn);

/**
 * @brief Injects ICMP header into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote bufer.
 * @param type Message type.
 * @param code Message code.
 * @return The function returns the pointer to ICMP packet.
 */
struct IcmpHeader *icmp_inject_header(unsigned char *buf, unsigned char type, unsigned char code);

/**
 * @brief Compute the ICMP checksum.
 * @param __IN__icmpHeader Pointer to remote ICMP packet.
 * @param paysize Size of ICMP payload.
 * @return The function returns the checksum.
 */
unsigned short icmp_checksum(struct IcmpHeader *icmpHeader, unsigned short paysize);

#endif

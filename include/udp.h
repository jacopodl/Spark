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
 * @file udp.h
 * @brief Provides useful functions for build and manage UDP packet.
 */

#ifndef SPARK_UDP_H
#define SPARK_UDP_H

#include "ip.h"

#define UDPHDRSIZE  8                                           // Header size
#define UDPMINSIZE  (UDPHDRSIZE + 0)                            // UDP min len

/// @brief This structure represents an UDP packet.
struct UdpHeader {
    /// @brief UDP source port.
    unsigned short srcport;
    /// @brief UDP destination port.
    unsigned short dstport;
    /// @brief UDP datagram length (UDPHDRSIZE + PAYLOAD LENGTH)
    unsigned short len;
    /// @brief UDP checksum.
    unsigned short checksum;
    /// @brief UDP payload.
    unsigned char data[];
}__attribute__((packed));

/**
 * @brief Built a new UDP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new UDP packet.
 * @param srcp Source port.
 * @param dstp Destination port.
 * @param paysize Length of payload.
 * @param payload UDP payload.
 * @return On success returns the pointer to new UDP packet of size equal to paysize + UDPHDRSIZE, otherwise return NULL.
 */
struct UdpHeader *udp_build_packet(unsigned short srcp, unsigned short dstp, unsigned short paysize,
                                   unsigned char *payload);

/**
 * @brief Injects UDP header into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote buffer.
 * @param srcp Source port.
 * @param dstp Destination port.
 * @param len Length of payload.
 * @return The function returns the pointer to UDP packet.
 */
struct UdpHeader *udp_inject_header(unsigned char *buf, unsigned short srcp, unsigned short dstp, unsigned short len);

/**
 * @brief Computes the UDP checksum.
 * @param __IN__udpHeader Pointer to remote UDP packet.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short udp_checksum(struct UdpHeader *udpHeader, struct Ipv4Header *ipv4Header);

#endif

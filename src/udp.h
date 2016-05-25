/*
* <udp, part of Spark.>
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
 * @file udp.h
 * @brief Provides useful functions for build and manage UDP packet.
 */

#ifndef SPARK_UDP_H
#define SPARK_UDP_H

#include "ipv4.h"

#define UDPHDRSIZE  8                                           // Header size
#define UDPMINSIZE  (UDPHDRSIZE + 0)                            // UDP min len
#define UDP4MAXSIZE (ETHMAXPAYL - (IPV4HDRSIZE + UDPHDRSIZE))   // UDP over IPv4 max len

/// @brief This structure rapresents an UDP packet.
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
};

/**
 * @brief Built a new UDP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new UDP packet and calculates the checksum.
 * @param srcp Source port.
 * @param dstp Destination port.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @param paysize Length of payload.
 * @param payload UDP payload.
 * @return On success returns the pointer to new UDP packet of size equal to paysize + UDPHDRSIZE, otherwise return NULL.
 */
struct UdpHeader *build_udp_packet(unsigned short srcp, unsigned short dstp, struct Ipv4Header *ipv4Header,
                                   unsigned short paysize, unsigned char *payload);

/**
 * @brief Injects UDP header into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param srcp Source port.
 * @param dstp Destination port.
 * @param len Length of payload.
 * @return The function returns the pointer to UDP packet.
 */
struct UdpHeader *injects_udp_header(unsigned char *buff, unsigned short srcp, unsigned short dstp, unsigned short len);

/**
 * @brief Computes the UDP checksum.
 * @param __IN__udpHeader Pointer to remote UDP packet.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short udp_checksum4(struct UdpHeader *udpHeader, struct Ipv4Header *ipv4Header);

#endif

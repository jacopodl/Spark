/*
* <tcp, part of Spark.>
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
 * @file tcp.h
 * @brief Provides useful functions for build and manage TCP packet.
 */

#ifndef SPARK_TCP_H
#define SPARK_TCP_H

#include "ipv4.h"

#define TCPHDRSIZE  20
#define TCPHDRLEN   5   // (TCPHDRSIZE / (DWORD/8))
#define TCPOPTSIZE  40
#define TCPMSSDEF   536


// Option
#define TCPOPT_EOPLIST  0
#define TCPOPT_NOOP     1
#define TCPOPT_MSS      2
#define TCPOPT_WSOP     3
#define TCPOPT_SACKP    4
#define TCPOPT_SACK     5
#define TCPOPT_ECHO     6
#define TCPOPT_ECHOR    7
#define TCPOPT_TSOPT    8
#define TCPOPT_POCP     9
#define TCPOPT_POSP     10
#define TCPOPT_CC       11
#define TCPOPT_CCNEW    12
#define TCPOPT_CCECHO   13
#define TCPOPT_ACR      14
#define TCPOPT_ACD      15
#define TCPOPT_MD5S     19
#define TCPOPT_QUICKSR  27
#define TCPOPT_USERTOUT 28
#define TCPOPT_TCPAO    29

/// @brief This structure rappresents an TCP packet.
struct TcpHeader {
    /// @brief Source port.
    unsigned short src;
    /// @brief Destination port.
    unsigned short dst;
    /// @brief Sequence number.
    unsigned int seqn;
    /// @brief Acknowledged sequence number.
    unsigned int ackn;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ecn_n:1;
    unsigned char rsv:3;
    unsigned char offset:4;
    union {
#define TCPCWR      0x80
#define TCPECNE     0x40
#define TCPURG      0x20
#define TCPACK      0x10
#define TCPPSH      0x08
#define TCPRST      0x04
#define TCPSYN      0x02
#define TCPFIN      0x01
        unsigned char flags;
        // Control Bits
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        // Explicit Congestion Notification
        unsigned char ecn_e:1;
        unsigned char ecn_c:1;
    };
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char offset:4;
    unsigned char rsv:3;
    unsigned char ecn_n:1;
    union {
#define TCPCWR      0x01
#define TCPECNE     0x02
#define TCPURG      0x04
#define TCPACK      0x08
#define TCPPSH      0x10
#define TCPRST      0x20
#define TCPSYN      0x40
#define TCPFIN      0x80
        unsigned char flags;
        // Explicit Congestion Notification
        unsigned char ecn_c:1;
        unsigned char ecn_e:1;
        // Control Bits
        unsigned char urg:1;
        unsigned char ack:1;
        unsigned char psh:1;
        unsigned char rst:1;
        unsigned char syn:1;
        unsigned char fin:1;
    };
#endif
    /// @brief TCP widnow size.
    unsigned short window;
    /// @brief TCP checksum.
    unsigned short checksum;
    /// @brief Urgent pointer.
    unsigned short urp;
    /// @brief TCP payload.
    unsigned char data[];
};

/**
 * @brief Built a new TCP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new TCP packet and calculates the checksum.
 * @param src Source port.
 * @param dst Destination port.
 * @param seqn Sequence number.
 * @param ackn Acknowledged sequence number.
 * @param flags TCP flags.
 * @param window Window size.
 * @param urgp Urgent pointer.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @param paysize Length of payload.
 * @param payload TCP payload.
 * @return On success returns the pointer to new TCP packet of size equal to paysize + TCPHDRSIZE, otherwise return NULL.
 */
struct TcpHeader *build_tcp_packet(unsigned short src, unsigned short dst, unsigned int seqn,
                                   unsigned int ackn, unsigned char flags,
                                   unsigned short window, unsigned short urgp, struct Ipv4Header *ipv4Header,
                                   unsigned long paysize,
                                   unsigned char *payload);

/**
 * @brief Injects TCP packet into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param src Source port.
 * @param dst Destination port.
 * @param seqn Sequence number.
 * @param ackn Acknowledged sequence number.
 * @param flags TCP flags.
 * @param window Window size.
 * @param urgp Urgent pointer.
 * @return The function returns the pointer to TCP packet.
 */
struct TcpHeader *injects_tcp_header(unsigned char *buff, unsigned short src, unsigned short dst, unsigned int seqn,
                                     unsigned int ackn, unsigned char flags,
                                     unsigned short window, unsigned short urgp);

/**
 * @brief Computes the TCP checksum.
 * @param __IN__TcpHeader Pointer to remote TCP packet.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short tcp_checksum4(struct TcpHeader *TcpHeader, struct Ipv4Header *ipv4Header);

#endif

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
 * @file tcp.h
 * @brief Provides useful functions for build and manage TCP packet.
 */

#ifndef SPARK_TCP_H
#define SPARK_TCP_H

#include "ip.h"

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
#define TCPCWR      0x80
#define TCPECNE     0x40
#define TCPURG      0x20
#define TCPACK      0x10
#define TCPPSH      0x08
#define TCPRST      0x04
#define TCPSYN      0x02
#define TCPFIN      0x01
    unsigned char flags;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char offset:4;
    unsigned char rsv:3;
    unsigned char ecn_n:1;
#define TCPCWR      0x01
#define TCPECNE     0x02
#define TCPURG      0x04
#define TCPACK      0x08
#define TCPPSH      0x10
#define TCPRST      0x20
#define TCPSYN      0x40
#define TCPFIN      0x80
        unsigned char flags;
#endif
    /// @brief TCP widnow size.
    unsigned short window;
    /// @brief TCP checksum.
    unsigned short checksum;
    /// @brief Urgent pointer.
    unsigned short urp;
    /// @brief TCP payload.
    unsigned char data[];
}__attribute__((packed));

/**
 * @brief Built a new TCP packet.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new TCP packet.
 * @param src Source port.
 * @param dst Destination port.
 * @param seqn Sequence number.
 * @param ackn Acknowledged sequence number.
 * @param flags TCP flags.
 * @param window Window size.
 * @param urgp Urgent pointer.
 * @param paysize Length of payload.
 * @param payload TCP payload.
 * @return On success returns the pointer to new TCP packet of size equal to paysize + TCPHDRSIZE, otherwise return NULL.
 */
struct TcpHeader *tcp_build_packet(unsigned short src, unsigned short dst, unsigned int seqn, unsigned int ackn,
                                   unsigned char flags, unsigned short window, unsigned short urgp,
                                   unsigned short paysize,
                                   unsigned char *payload);

/**
 * @brief Injects TCP packet into a buffer pointed by `buf`.
 * @param __OUT__buf Pointer to remote buffer.
 * @param src Source port.
 * @param dst Destination port.
 * @param seqn Sequence number.
 * @param ackn Acknowledged sequence number.
 * @param flags TCP flags.
 * @param window Window size.
 * @param urgp Urgent pointer.
 * @return The function returns the pointer to TCP packet.
 */
struct TcpHeader *tcp_inject_header(unsigned char *buf, unsigned short src, unsigned short dst, unsigned int seqn,
                                    unsigned int ackn, unsigned char flags, unsigned short window,
                                    unsigned short urgp);

/**
 * @brief Computes the TCP checksum.
 * @param __IN__TcpHeader Pointer to remote TCP packet.
 * @param __IN__ipv4Header Pointer to ipv4 header.
 * @return The function returns the checksum.
 */
unsigned short tcp_checksum(struct TcpHeader *TcpHeader, struct Ipv4Header *ipv4Header);

#endif

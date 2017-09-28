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
 * @file spksock.h
 * @brief Provides uniform APIs for create, manage, destroy and use raw sockets.
 */

#ifndef SPARK_SPKSOCK_H
#define SPARK_SPKSOCK_H

#include <stdbool.h>

#include "spkerr.h"
#include "datatype.h"
#include "dlt_table.h"

/// @brief Define packets direction.
enum SpkDirection {
    SPKDIR_IN = 0x01,
    SPKDIR_OUT = 0x02,
    SPKDIR_BOTH = 0x03
};

/// @brief Define the timestamp precision.
enum SpkTimesPrc {
    SPKSTAMP_MICRO, // microsecond precision, default
    SPKSTAMP_NANO   // nanosecond precision
};

/// @brief Represent the packet timestamp with the selected precision.
struct SpkTimeStamp {
    /// @brief Second.
    long sec;
    /// @brief Sub-second precision, Microsecond/Nanosecond
    long subs;
    /// @brief Timestamp precision.
    enum SpkTimesPrc prc;
};

/// @brief Socket statistics.
struct SpkStats {
    /// @brief Total packets received.
    unsigned long pkt_recv;
    /// @brief Packets sent.
    unsigned long pkt_send;
    /// @brief Total bytes received.
    unsigned long rx_byte;
    /// @brief Bytes sent.
    unsigned long tx_byte;
};

/// @brief Contains information about the active raw socket (this struct is private).
struct SpkSock {
    char *iface_name;
    struct netaddr_mac iaddr;
    unsigned int bufl;
    int sfd;
    int lktype;
    enum SpkTimesPrc tsprc;
    enum SpkDirection direction;
    struct SpkStats sock_stats;
    void *aux;

    struct {
        int (*read)(struct SpkSock *, unsigned char *, struct SpkTimeStamp *);

        int (*setdir)(struct SpkSock *, enum SpkDirection);

        int (*setprc)(struct SpkSock *, enum SpkTimesPrc);

        int (*setpromisc)(struct SpkSock *, bool promisc);

        int (*write)(struct SpkSock *, unsigned char *, unsigned int);

        int (*setnblk)(struct SpkSock *, bool nonblock);

        void (*finalize)(struct SpkSock *);
    } op;
};

/**
 * @brief Returns the link type in use.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @return On success, returns DLT value, otherwise returns -1.
 */
int spark_getltype(struct SpkSock *ssock);

/**
 * @brief Open raw socket on selected network device.
 * @param device Interface name.
 * @param bufl Set length of buffer for read operation.
 * @param __OUT__ssock Pointer to the empty SpkSock structure.
 * @return Upon successful completion, spark_opensock() returns SPKERR_SUCCESS.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_opensock(char *device, unsigned int buflen, struct SpkSock **ssock);

/**
 * @brief Receive data from the raw socket.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param __OUT__buf Pointer to buffer.
 * @param __OUT__ts Pointer to SpkTimeStamp structure to handle packet timestamp (can be NULL).
 * @return Upon successful completion, spark_read() shall return the length of the packet in bytes.
 * If no messages are available spark_read() shall return 0.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_read(struct SpkSock *ssock, unsigned char *buf, struct SpkTimeStamp *ts);

/**
 * @brief Set packets direction filter.
 *
 * Set the setting determining whether incoming, outgoing,
 * or both packets on the interface should be returned by raw socket.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param direction Packets direction.
 * @return On success, SPKERR_SUCCESS is returned.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_setdirection(struct SpkSock *ssock, enum SpkDirection direction);

/**
 * @brief Set socket blocking mode.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param nonblock True or false.
 * @return On success, SPKERR_SUCCESS is returned.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_setnblock(struct SpkSock *ssock, bool nonblock);

/**
 * @brief Set promiscuous mode.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param promisc True or false.
 * @return On success, SPKERR_SUCCESS is returned.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 * @warning On BSD systems this option involves the whole device and not only the socket.
 */
int spark_setpromisc(struct SpkSock *ssock, bool promisc);

/**
 * @brief Set timestamp precision.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param prc Timestamp precision.
 * @return On success, SPKERR_SUCCESS is returned.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_settsprc(struct SpkSock *ssock, enum SpkTimesPrc prc);

/**
 * @brief Send data to the raw socket.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param __IN__buf Pointer to buffer.
 * @param len Buffer length.
 * @return On success, the number of bytes written is returned.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_write(struct SpkSock *ssock, unsigned char *buf, unsigned int len);

/**
 * @brief Close raw socket.
 *
 * Close raw socket and release memory used by SpkSock.
 * @param __IN__ssock Pointer to SpkSock of the active socket.
 */
void spark_close(struct SpkSock *ssock);

/**
 * @brief Obtains socket statistics.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param __OUT__stats Pointer to SpkStats.
 */
void spark_getsstats(struct SpkSock *ssock, struct SpkStats *stats);

/**
 * @brief Sets the buffer length for reading operations.
 * @param __IN__ssock Pointer to SpkSock structure which handles the active raw socket.
 * @param size New buffer size.
 */
void spark_setbuf(struct SpkSock *ssock, unsigned int size);

#endif

/*
* llsock, part of Spark.
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
 * @file llsock.h
 * @brief Provides a uniform APIs for create, destroy and use raw sockets.
 */

#ifndef SPARK_LLSOCK_H
#define SPARK_LLSOCK_H

#include <stdbool.h>
#include <net/if.h>
#include "datatype.h"
#include "ethernet.h"

#define LLSOCK_DEFRBUF  (ETHFRAME)
#define LLSOCK_BPFPATHMAXLEN   11
#define LLSOCK_BPFMAXDEV       99

#define LLSOCK_GETDFD(llsi)  (llsi.sfd)
#define LLSOCK_GETBUF(llsi)  (llsi.buffl)

#define LLRECV2(BUFF, LLSI)                 llrecv2(BUFF,LLSI)
#define LLRECV3(BUFF, LEN, LLSI)            llrecv3(BUFF,LEN,LLSI)
#define GET_LLRECV(_1, _2, _3, NAME, ...)   NAME
#define llrecv(...)                         GET_LLRECV(__VA_ARGS__,LLRECV3,LLRECV2)(__VA_ARGS__)

/// @brief Contains information about the active raw socket.
struct llSockInfo {
    /// @brief Contains interface name, Eg: eno1, wlo1...
    char iface_name[IFNAMSIZ];
    /// @brief Contains interface MAC address.
    struct netaddr_mac iface_mac;
    /// @brief Contains the path of the BPF device in used.
    char bpf_path[LLSOCK_BPFPATHMAXLEN];
    /// @brief Socket descriptor.
    int sfd;
    /// @brief Buffer length for the read operations.
    unsigned long buffl;
};

/**
 * @brief Close raw socket.
 *
 * Close raw socket and if `freemem` is true, release memory used by llSockInfo.
 * @param __IN__llo Pointer to llSockInfo of the active socket.
 * @param freemem Release memory?
 * @return llclose() returns 0 on success.
 * On error, -1 is returned, and errno is set appropriately.
 */
int llclose(struct llSockInfo *llsi, bool freemem);

/**
 * @brief Open raw socket on selected network device.
 * @param __OUT__llo Pointer to the empty llSockInfo structure.
 * @param iface_name Interface name.
 * @param buffl Set length of buffer for read operation.
 * @return Upon successful completion, llsocket() returns the socket file descriptor.
 * Otherwise, a value of -1 shall be returned and errno set to indicate the error.
 */
int llsocket(struct llSockInfo *llsi, char *iface_name, unsigned int buffl);

/**
 * @brief Receive data from the raw socket.
 * @param __OUT__buff Pointer to buffer.
 * @param __IN__llo Pointer to llSockInfo structure which handles the active raw socket.
 * @return Upon successful completion, llrecv() shall return the length of the message in bytes.
 * If no messages are available llrecv() shall return 0.
 * Otherwise, −1 shall be returned and errno set to indicate the error.
 */
ssize_t llrecv2(void *buff, struct llSockInfo *llsi);

/**
 * @brief Receive data from the raw socket.
 * @param __OUT__buff Pointer to buffer.
 * @param __IN__llo Pointer to llSockInfo structure which handles the active raw socket.
 * @param buffl Buffer length.
 * @return Upon successful completion, llrecv() shall return the length of the message in bytes.
 * If no messages are available llrecv() shall return 0.
 * Otherwise, −1 shall be returned and errno set to indicate the error.
 */
ssize_t llrecv3(void *buff, unsigned long len, struct llSockInfo *llsi);

/**
 * @brief Send data to the raw socket.
 * @param __IN__buff Pointer to buffer.
 * @param len Buffer length.
 * @param __IN__llo Pointer to llSockInfo structure which handles the active raw socket.
 * @return On success, the number of bytes written is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
ssize_t llsend(const void *buff, unsigned long len, struct llSockInfo *llsi);

#endif

/*
* <netdevice, part of Spark.>
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
 * @file netdevice.h
 * @brief Provides a uniform APIs for create, destroy and use raw sockets, 
 * in addition provides the functions for manage network devices.
 */

#ifndef SPARK_NETDEVICE_H
#define SPARK_NETDEVICE_H

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include "datatype.h"

#define BPFPATHMAXLEN   11
#define BPFMAXDEV       99

#define NETD_UNSUCCESS      0
#define NETD_SUCCESS        1
#define NETD_NOTSUPPORTED    -1

/// @brief Contains information about the active raw socket.
struct llOptions {
	/// @brief Contains interface name, Eg: eno1, wlo1...
    char iface_name[IFNAMSIZ];
	/// @brief Contains the path of the BPF device used.	
    char bsd_bind[BPFPATHMAXLEN];
	/// @brief Socket descriptor.
    int sfd;
	/// @brief Buffer length for the read operations.
    unsigned long buffl;
};

/// @brief Contains device name and pointer to the next structure.
struct ifList {
	/// @brief Device name.
    char name[IFNAMSIZ];
	/// @brief Next ifList item.
    struct ifList *next;
};

/**
 * @brief Obtains device burned-in mac address.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param __OUT__hwa Pointer to netaddr_mac structure.
 * @return The get_burnedin_mac and get_hwaddr functions returns NETD_SUCCESS and fill hwa with mac address.
 * On error, NETD_UNSUCCESS is returned. If function is not supported NETD_NOTSUPPORTED is returned.
 * @warning On BSD systems this function returns always NETD_NOTSUPPORTED.
 */
int get_burnedin_mac(int sd, char *iface_name, struct netaddr_mac *hwa);

/**
 * @brief Get the active flag word of the device.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param __OUT__flag Pointer to short int.
 * @return On success the parameter `flag` will filled with active device flags and the function returns NETD_SUCCESS.
 * Otherwise, NETD_UNSUCCESS is returned.
 */
int get_flags(int sd, char *iface_name, short *flag);

/**
 * @brief Obtains current device mac address.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param __OUT__hwaddr Pointer to netaddr_mac structure.
 * @return The get_burnedin_mac and get_hwaddr functions returns NETD_SUCCESS and fill hwaddr with mac address.
 * On error, NETD_UNSUCCESS is returned.
 */
int get_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

/**
 * @brief Close raw socket.
 *
 * Close raw socket and if `freemem` is true, release memory used by llOptions.
 * @param __IN__llo Pointer to llOptions of the active socket.
 * @param freemem Release memory?
 * @return llclose() returns 0 on success. 
 * On error, -1 is returned, and errno is set appropriately.
 */
int llclose(struct llOptions *llo, bool freemem);

/**
 * @brief Open raw socket on selected network device.
 * @param __OUT__llo Pointer to the empty llOptions structure.
 * @param iface_name Interface name.
 * @param buffl Set length of buffer for read operation.
 * @return Upon successful completion, llsocket() returns the socket file descriptor. 
 * Otherwise, a value of -1 shall be returned and errno set to indicate the error.
 */
int llsocket(struct llOptions *llo, char *iface_name, unsigned int buffl);

/**
 * @brief Set device flags.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param flags New device flags word.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_UNSUCCESS is returned, and errno is set appropriately.
 */
int set_flags(int sd, char *iface_name, short flags);

/**
 * @brief Set new mac address.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param __IN__hwaddr Pointer to netaddr_mac structure contains new mac address.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_UNSUCCESS is returned, and errno is set appropriately.
 */
int set_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

/**
 * @brief Receive data from the raw socket.
 * @param __OUT__buff Pointer to buffer.
 * @param __IN__llo Pointer to llOptions structure which handles the active raw socket.
 * @return Upon successful completion, llrecv() shall return the length of the message in bytes. 
 * If no messages are available llrecv() shall return 0.
 * Otherwise, −1 shall be returned and errno set to indicate the error.
 */
ssize_t llrecv(void *buff, struct llOptions *llo);

/**
 * @brief Send data to the raw socket.
 * @param __IN__buff Pointer to buffer.
 * @param len Buffer length.
 * @param __IN__llo Pointer to llOptions structure which handles the active raw socket.
 * @return On success, the number of bytes written is returned.
 * On error, -1 is returned, and errno is set appropriately. 
 */
ssize_t llsend(const void *buff, unsigned long len, struct llOptions *llo);

/**
 * @brief Builds and returns linked list with devices currently availlable on the system.
 * @param filter Set this mask for ignore a certain device group, Eg: IFF_BROADCAST, IFF_PROMISC...
 * @return First element of the ifList linked list.
 * On error, NULL is returned.
 */
struct ifList *get_iflist(unsigned int filter);

/**
 * @brief Frees the memory occupied by get_iflist() function.
 * @param __IN__ifList first element of ifList linked list built with get_iflist() function.
 */
void iflist_cleanup(struct ifList *ifList);

static void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl);

#endif

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
 * @brief Create/destroy raw scoket and manage NIC information.
 *
 * This file provides generic APIs (Linux/BSD) for create raw socket and manage
 * network device, you can easily get list of all availlable device and allows you
 * to modified certain device parameters such as: mac address, NIC flags.
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

/**
 * @brief Contains information about the open socket.
 */
struct llOptions {
	/// @brief Contain interface name, Eg: eno1, wlo1...
    char iface_name[IFNAMSIZ];
	/// @brief Path of the bound BPF device.	
    char bsd_bind[BPFPATHMAXLEN];
	/// @brief Socket descriptor.
    int sfd;
	/// @brief Buffer length for the read operations.
    unsigned long buffl;
};

/**
 * @brief Contains device name and pointer to the next structure.
 */
struct ifList {
	/// @brief Device name.
    char name[IFNAMSIZ];
	/// @brief Next ifList item.
    struct ifList *next;
};

/**
 * @brief Get the device burned-in mac address.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param hwa Pointer to netaddr_mac structure.
 * @return Upon successful completion hwa will filled with mac address and funcion returns NETD_SUCCESS.
 * Otherwise, NETD_UNSUCCESS is returned. If function is not supported NETD_NOTSUPPORTED is returned.
 * @warning On BSD systems this function returns always NETD_NOTSUPPORTED.
 */
int get_burnedin_mac(int sd, char *iface_name, struct netaddr_mac *hwa);

/**
 * @brief Get the active flag word of the device.
 * @param sd Socket descriptor.
 * @param iface_name Interface name.
 * @param flag Pointer to short int.
 * @return Upon successful completion flag will filled with active FLGAS and funcion returns NETD_SUCCESS.
 * Otherwise, NETD_UNSUCCESS is returned.
 */
int get_flags(int sd, char *iface_name, short *flag);

int get_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

int llclose(struct llOptions *llo, bool freemem);

int llsocket(struct llOptions *llo, char *iface_name, unsigned int buffl);

int set_flags(int sd, char *iface_name, short flags);

int set_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

ssize_t llrecv(void *buff, struct llOptions *llo);

ssize_t llsend(const void *buff, unsigned long len, struct llOptions *llo);

struct ifList *get_iflist(unsigned int filter);

void iflist_cleanup(struct ifList *ifList);

static void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl);

#endif

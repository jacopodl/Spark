/*
* <netdevice, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
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
 * @file netdevice.h
 * @brief Provides functions for manage network devices.
 */

#ifndef SPARK_NETDEVICE_H
#define SPARK_NETDEVICE_H

#include <stdbool.h>
#include <net/if.h>
#include "datatype.h"

#define NETD_UNSUCCESS      0
#define NETD_SUCCESS        1
#define NETD_NOTSUPPORTED    -1


/// @brief Contains device information and pointer to the next structure.
struct ifList {
    /// @brief Device name.
    char name[IFNAMSIZ];
    /// @brief Device flags.
    unsigned int flags;
    /// @brief Device MAC address.
    struct netaddr_mac mac;
    /// @brief Next ifList item.
    struct ifList *next;
};

/**
 * @brief Obtains device burned-in mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The get_device_burnedin_mac and get_device_mac functions returns NETD_SUCCESS and fill hwa with mac address.
 * On error, NETD_UNSUCCESS is returned and errno is set appropriately. If function is not supported NETD_NOTSUPPORTED is returned.
 * @warning On BSD systems this function returns always NETD_NOTSUPPORTED.
 */
int get_device_burnedin_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Get the active flag word of the device.
 * @param iface_name Interface name.
 * @param __OUT__flag Pointer to short int.
 * @return On success the parameter `flag` will filled with active device flags and the function returns NETD_SUCCESS.
 * Otherwise, NETD_UNSUCCESS is returned and errno is set appropriately.
 */
int get_device_flags(char *iface_name, short *flag);

/**
 * @brief Obtains current device mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The get_device_mac and get_device_mac functions returns NETD_SUCCESS and fill hwaddr with mac address.
 * On error, NETD_UNSUCCESS is returned and errno is set appropriately.
 */
int get_device_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Builds and returns linked list with devices currently availlable on the system.
 * @param filter Set this mask for showing a certain device group, Eg: IFF_BROADCAST, IFF_PROMISC...
 * If mask is ZERO all device are displayed.
 * @return First element of the ifList linked list.
 * On error, NULL is returned.
 */
int get_iflist(unsigned int filter, struct ifList **iflist);

/**
 * @brief Set device flags.
 * @param iface_name Interface name.
 * @param flags New device flags word.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_UNSUCCESS is returned, and errno is set appropriately.
 */
int set_device_flags(char *iface_name, short flags);

/**
 * @brief Set new mac address..
 * @param iface_name Interface name.
 * @param __IN__mac Pointer to netaddr_mac structure contains new mac address.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_UNSUCCESS is returned, and errno is set appropriately.
 */
int set_device_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Frees the memory occupied by get_iflist() function.
 * @param __IN__ifList first element of ifList linked list built with get_iflist() function.
 */
void iflist_cleanup(struct ifList *ifList);

#endif

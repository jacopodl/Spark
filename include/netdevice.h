/*
 * Copyright (c) 2016 Jacopo De Luca
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
 * @file netdevice.h
 * @brief Provides functions for manage network devices.
 */

#ifndef SPARK_NETDEVICE_H
#define SPARK_NETDEVICE_H

#include <stdbool.h>
#include <net/if.h>

#include "datatype.h"

#define NETD_SUCCESS    1
#define NETD_FAILURE    0
#define NETD_ENOSUPPORT -1


/// @brief Contains device information and pointer to the next structure.
struct NetDevList {
    /// @brief Device name.
    char name[IFNAMSIZ];
    /// @brief Device flags.
    unsigned int flags;
    /// @brief Device MAC address.
    struct netaddr_mac mac;
    /// @brief Next NetDevList item.
    struct NetDevList *next;
};

/**
 * @brief Obtains device burned-in mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The netdev_burnedin_mac and netdev_get_mac functions returns NETD_SUCCESS and fill mac with MAC address.
 * On error, NETD_FAILURE is returned and errno is set appropriately. If function is not supported NETD_ENOSUPPORT is returned.
 */
int netdev_burnedin_mac(char *iface_name, struct netaddr_mac *mac) ;

/**
 * @brief Get the active flag word of the device.
 * @param iface_name Interface name.
 * @param __OUT__flag Pointer to short int.
 * @return On success the parameter `flag` will filled with active device flags and the function returns NETD_SUCCESS.
 * Otherwise, NETD_FAILURE is returned and errno is set appropriately.
 */
int netdev_get_flags(char *iface_name, short *flags);

/**
 * @brief Obtains current device mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The netdev_get_mac and netdev_burnedin_mac functions returns NETD_SUCCESS and fill mac with MAC address.
 * On error, NETD_FAILURE is returned and errno is set appropriately.
 */
int netdev_get_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Set device flags.
 * @param iface_name Interface name.
 * @param flags New device flags word.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_FAILURE is returned, and errno is set appropriately.
 */
int netdev_set_flags(char *iface_name, short flags);

/**
 * @brief Set new mac address..
 * @param iface_name Interface name.
 * @param __IN__mac Pointer to netaddr_mac structure contains new MAC address.
 * @return On success NETD_SUCCESS is returned. 
 * Otherwise, NETD_FAILURE is returned, and errno is set appropriately.
 */
int netdev_set_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Builds and returns linked list with devices currently availlable on the system.
 * @param filter Set this mask for showing a certain device group, Eg: IFF_BROADCAST, IFF_PROMISC...
 * If mask is ZERO all device are displayed.
 * @return First element of the NetDevList linked list.
 * On error, NULL is returned.
 */
struct NetDevList *netdev_get_iflist(unsigned int filter);

/**
 * @brief Frees the memory occupied by netdev_get_iflist() function.
 * @param __IN__NetDevList pointer to NetDevList list.
 */
void netdev_iflist_cleanup(struct NetDevList *NetDevList);

#endif

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
 * @file netdevice.h
 * @brief Provides functions for manage network devices.
 */

#ifndef SPARK_NETDEVICE_H
#define SPARK_NETDEVICE_H

#include <stdbool.h>
#include <net/if.h>

#include "datatype.h"

#define ROUTETABLE   "/proc/net/route"

/// @brief Contains device information and pointer to the next structure.
struct NetDevice {
    /// @brief Device name.
    char name[IFNAMSIZ];
    /// @brief Device flags.
    unsigned int flags;
    /// @brief Device MAC address.
    struct netaddr_mac mac;
    /// @brief Next NetDevice item.
    struct NetDevice *next;
};

/**
 * @brief Obtains device burned-in mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The netdev_burnedin_mac and netdev_get_mac functions returns SPKERR_SUCCESS and fill mac with MAC address.
 * On error, SPKERR_ERROR is returned and errno is set appropriately. If function is not supported SPKERR_ENOSUPPORT is returned.
 */
int netdev_burnedin_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Get the active flag word of the device.
 * @param iface_name Interface name.
 * @param __OUT__flag Pointer to short int.
 * @return On success the parameter `flag` will filled with active device flags and the function returns SPKERR_SUCCESS.
 * Otherwise, SPKERR_ERROR is returned.
 */
int netdev_get_flags(char *iface_name, short *flags);

/**
 * @brief Obtains the address of default gateway.
 * @param iface_name Interface name.
 * @param __OUT__gateway Pointer to netaddr_ip structure.
 * @return Function returns SPKERR_SUCCESS if the gateway address has been obtained, SPKERR_ERROR otherwise.
 * If function is not supported SPKERR_ENOSUPPORT is returned.
 */
int netdev_get_defgateway(char *iface_name, struct netaddr_ip *gateway);

/**
 * @brief Obtains the IPv4 address.
 * @param iface_name Interface name.
 * @param __OUT__ip Pointer to netaddr_ip structure.
 * @return Function returns SPKERR_SUCCESS if the address has been obtained, SPKERR_ERROR otherwise.
 */
int netdev_get_ip(char *iface_name, struct netaddr_ip *ip);

/**
 * @brief Obtains current device mac address.
 * @param iface_name Interface name.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @return The netdev_get_mac and netdev_burnedin_mac functions returns SPKERR_SUCCESS and fill mac with MAC address.
 * On error, SPKERR_ERROR is returned and errno is set appropriately.
 */
int netdev_get_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Obtains interface MTU.
 * @param iface_name Interface name.
 * @return if succeeded returns MTU, otherwise SPKERR_ERROR.
 */
int netdev_get_mtu(char *iface_name);

/**
 * @brief Obtains the IPv4 netmask.
 * @param iface_name Interface name.
 * @param __OUT__netmask Pointer to netaddr_ip structure.
 * @return Function returns SPKERR_SUCCESS if netmask has been obtained, SPKERR_ERROR otherwise.
 */
int netdev_get_netmask(char *iface_name, struct netaddr_ip *netmask);

/**
 * @brief Set device flags.
 * @param iface_name Interface name.
 * @param flags New device flags word.
 * @return On success SPKERR_SUCCESS is returned.
 * Otherwise, SPKERR_ERROR is returned, and errno is set appropriately.
 */
int netdev_set_flags(char *iface_name, short flags);

/**
 * @brief Set new mac address.
 * @param iface_name Interface name.
 * @param __IN__mac Pointer to netaddr_mac structure contains new MAC address.
 * @return On success SPKERR_SUCCESS is returned.
 * Otherwise, SPKERR_ERROR is returned, and errno is set appropriately.
 */
int netdev_set_mac(char *iface_name, struct netaddr_mac *mac);

/**
 * @brief Set interface MTU.
 * @param iface_name Interface name.
 * @param mtu New MTU value.
 * @return On success SPKERR_SUCCESS is returned.
 * Otherwise, SPKERR_ERROR is returned, and errno is set appropriately.
 */
int netdev_set_mtu(char *iface_name, int mtu);

/**
 * @brief Builds and returns linked list with devices currently availlable on the system.
 * @param filter Set this mask for showing a certain device group, Eg: IFF_BROADCAST, IFF_PROMISC...
 * If mask is ZERO all device are displayed.
 * @return First element of the NetDevice linked list.
 * On error, NULL is returned.
 */
struct NetDevice *netdev_get_iflist(unsigned int filter);

/**
 * @brief Frees the memory occupied by netdev_get_iflist() function.
 * @param __IN__NetDevice pointer to NetDevice list.
 */
void netdev_iflist_cleanup(struct NetDevice *NetDevice);

#endif

/*
* <ethernet, part of Spark.>
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
 * @file ethernet.h
 * @brief Provides useful functions for build Ethernet frames and manage related addresses.
 */

#ifndef SPARK_ETHERNET_H
#define SPARK_ETHERNET_H

#include <stdbool.h>
#include "datatype.h"

#define ETHHWASIZE      6       // Ethernet addr byte len
#define MACSTRSIZE      18      // Mac addr string size
#define MACSTRHLFSIZE   9       // Mac addr string half size
#define ETHHDRSIZE      14      // Ethernet header size
#define ETHMINPAYL      64      // Ethernet min payload
#define ETHMAXPAYL      1500    // Ethernet max payload

#define ETHTYPE_PUP     0X0200
#define ETHTYPE_IP      0x0800
#define ETHTYPE_ARP     0X0806
#define ETHTYPE_RARP    0X8035

/// @brief This structure rappresents an Ethernet frame.
struct EthHeader {
	/// @brief Destination hardware address.
    unsigned char dhwaddr[ETHHWASIZE];
    /// @brief Source hardware address.
    unsigned char shwaddr[ETHHWASIZE];
    /// @brief Ethernet type.
    unsigned short eth_type;
    /// @brief Ethernet payload.
    unsigned char data[];
};

/**
 * @brief Compare two mac address.
 * @param mac1 Pointer to netaddr_mac structure contains first mac address.
 * @param mac2 Pointer to netaddr_mac structure contains seconds mac address.
 * @return Function returns true if mac1 is equals to mac2, false otherwise.
 */
bool ethcmp(struct netaddr_mac *mac1, struct netaddr_mac *mac2);

/**
 * @brief Parse string contains a mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param hwstr String contains mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param __OUT__ret_hwaddr Pointer to netaddr_mac structure.
 * @return Function returns true if the address has been converted, false otherwise.
 */
bool parse_hwaddr(char *hwstr, struct netaddr_mac *ret_hwaddr, bool bcast);

/**
 * @brief Obtains mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param __IN__hwa Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static buffer.
 * @return Function returns string contains mac address.
 */
char *get_strhwaddr(struct netaddr_mac *hwa, bool _static);

/**
 * @brief Obtains mac address serial(S) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__hwa Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static buffer.
 * @return Function returns string contains serial.
 */
char *get_serial(struct netaddr_mac *hwa, bool _static);

/**
 * @brief Obtains mac address vendor(V) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__hwa Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static buffer.
 * @return Function returns string contains vendor.
 */
char *get_vendor(struct netaddr_mac *hwa, bool _static);

/**
 * @brief Built a new Ethernet frames.
 *
 * If `payload` is not NULL, the functions copies all byte from payload buffer in the new Ethernet frame.
 * @param __IN__src Pointer to netaddr_mac structure contains source mac address.
 * @param __IN__dst Pointer to netaddr_mac structure contains destination mac address.
 * @param type Ethernet frame type.
 * @param paysize Lenght of paylod.
 * @param payload Ethernet payload.
 * @return On success returns the pointer to new Ethernet frame of size equal to paysize + ETHHDRSIZE, otherwise return NULL.
 */
struct EthHeader *build_ethernet_packet(struct netaddr_mac *src, struct netaddr_mac *dst, unsigned short type,
                                        unsigned long paysize, unsigned char *payload);

/**
 * @brief Injects Ethernet frame into a buffer pointed by `buff`.
 * @param __OUT__buff Pointer to remote buffer.
 * @param __IN__src Pointer to netaddr_mac structure contains source mac address.
 * @param __IN__dst Pointer to netaddr_mac structure contains destination mac address.
 * @param type Ethernet frame type.
 * @return The function returns the pointer to Ethernet frame.
 */
struct EthHeader *injects_ethernet_header(unsigned char *buff, struct netaddr_mac *src, struct netaddr_mac *dst,
                                          unsigned short type);

/**
 * @brief Builds broadcast mac address.
 * @param __OUT__addr Pointer to netaddr_mac structure.
 */
void build_ethbroad_addr(struct netaddr_mac *addr);

/**
 * @brief Builds multicast mac address.
 * @param __OUT__hw Pointer to netaddr_mac structure.
 * @param __IN__ip Pointer to netaddr_ip structure.
 */
void build_ethmulti_addr(struct netaddr_mac *hw, struct netaddr_ip *ip);

/**
 * @brief Obtains a random mac address.
 *
 * The mac address returned is never a broadcast or multicast address!
 * @param __OUT__mac Pointer to netaddr_mac structure.
 */
void rndhwaddr(struct netaddr_mac *mac);

#endif

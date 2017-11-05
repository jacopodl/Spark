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
 * @file ethernet.h
 * @brief Provides useful functions for build Ethernet frames and manage related addresses.
 */

#ifndef SPARK_ETHERNET_H
#define SPARK_ETHERNET_H

#include <stdbool.h>
#include "datatype.h"

#define ETHHWASIZE      6       // Ethernet addr byte len
#define ETHSTRLEN       18      // Mac address string size
#define ETHSTRHLFLEN    9       // Mac address string half size

#define ETHFRAME        1514    // (Dst + Src + Type) + ETHMAXPAYL
#define ETHHDRSIZE      14      // Ethernet header size
#define ETHMINPAYL      46      // Ethernet min payload
#define ETHMAXPAYL      1500    // Ethernet max payload

#define ETHTYPE_PUP     0x0200
#define ETHTYPE_IP      0x0800
#define ETHTYPE_IPV6    0x86DD
#define ETHTYPE_ARP     0x0806
#define ETHTYPE_RARP    0x8035
#define ETHTYPE_MPLSU   0x8847 // MPLS unicast
#define ETHTYPE_MPLSM   0x8848 // MPLS multicast

/// @brief This structure represents an Ethernet frame.
struct EthHeader {
    /// @brief Destination hardware address.
    unsigned char dhwaddr[ETHHWASIZE];
    /// @brief Source hardware address.
    unsigned char shwaddr[ETHHWASIZE];
    /// @brief Ethernet type.
    unsigned short eth_type;
    /// @brief Ethernet payload.
    unsigned char data[];
}__attribute__((packed));

/**
 * @brief Compare two mac address.
 * @param mac1 Pointer to netaddr_mac structure contains first mac address.
 * @param mac2 Pointer to netaddr_mac structure contains seconds mac address.
 * @return Function returns true if mac1 is equals to mac2, false otherwise.
 */
bool eth_equals(struct netaddr_mac *mac1, struct netaddr_mac *mac2);

/**
 * @brief Checks if is a broadcast mac address.
 * @param mac Pointer to netaddr_mac structure contains mac address.
 * @return Function returns true if is a broadcast mac address, false otherwise.
 */
bool eth_isbcast(struct netaddr_mac *mac);

/**
 * @brief Checks if is a empty mac address (All byte are zero!).
 * @param mac Pointer to netaddr_mac structure contains mac address.
 * @return Function returns true if is a empty mac address, false otherwise.
 */
bool eth_isempty(struct netaddr_mac *mac);

/**
 * @brief Parse string contains a mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param hwstr String contains mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @param bcast Allow broadcast addresses.
 * @return Function returns true if the address has been converted, false otherwise.
 */
bool eth_parse_addr(char *hwstr, struct netaddr_mac *mac, bool bcast);

/**
 * @brief Obtains mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static bufer.
 * @return Function returns string contains mac address.
 */
char *eth_getstr(struct netaddr_mac *mac, bool _static);

/**
 * @brief Obtains mac address in the form `XX:XX:XX:XX:XX:XX`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param __OUT__macstr Pointer to string of dimension ETHSTRLEN.
 * @return Function returns string contains mac address.
 */
char *eth_getstr_r(struct netaddr_mac *mac, char *macstr);

/**
 * @brief Obtains mac address serial(S) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static bufer.
 * @return Function returns string contains serial.
 */
char *eth_getstr_serial(struct netaddr_mac *mac, bool _static);

/**
 * @brief Obtains mac address serial(S) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param __OUT__sstr Pointer to string of dimension ETHSTRHLFLEN.
 * @return Function returns string contains serial.
 */
char *eth_getstr_serial_r(struct netaddr_mac *mac, char *sstr);

/**
 * @brief Obtains mac address vendor(V) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param _static Not allocate new memory, the result will be saved in a static bufer.
 * @return Function returns string contains vendor.
 */
char *eth_getstr_vendor(struct netaddr_mac *mac, bool _static);

/**
 * @brief Obtains mac address vendor(V) `VV:VV:VV:SS:SS:SS`.
 * @param __IN__mac Pointer to netaddr_mac structure contains mac address.
 * @param __OUT__vstr Pointer to string of dimension ETHSTRHLFLEN.
 * @return Function returns string contains vendor.
 */
char *eth_getstr_vendor_r(struct netaddr_mac *mac, char *vstr);

/**
 * @brief Built a new Ethernet frames.
 *
 * If `payload` is not NULL, the functions copies all byte from payload bufer in the new Ethernet frame.
 * @param __IN__src Pointer to netaddr_mac structure contains source mac address.
 * @param __IN__dst Pointer to netaddr_mac structure contains destination mac address.
 * @param type Ethernet frame type.
 * @param paysize Lenght of paylod.
 * @param payload Ethernet payload.
 * @return On success returns the pointer to new Ethernet frame of size equal to paysize + ETHHDRSIZE, otherwise return NULL.
 */
struct EthHeader *eth_build_packet(struct netaddr_mac *src, struct netaddr_mac *dst, unsigned short type,
                                   unsigned short paysize, unsigned char *payload);

/**
 * @brief Injects Ethernet header into a bufer pointed by `buf`.
 * @param __OUT__buf Pointer to remote bufer.
 * @param __IN__src Pointer to netaddr_mac structure contains source mac address.
 * @param __IN__dst Pointer to netaddr_mac structure contains destination mac address.
 * @param type Ethernet frame type.
 * @return The function returns the pointer to Ethernet frame.
 */
struct EthHeader *eth_inject_header(unsigned char *buf, struct netaddr_mac *src, struct netaddr_mac *dst,
                                    unsigned short type);

/**
 * @brief Builds broadcast mac address.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 */
void eth_bcast(struct netaddr_mac *mac);

/**
 * @brief Builds multicast mac address.
 * @param __OUT__mac Pointer to netaddr_mac structure.
 * @param __IN__ip Pointer to netaddr_ip structure.
 */
void eth_multi(struct netaddr_mac *mac, struct netaddr_ip *ip);

/**
 * @brief Obtains a random mac address.
 *
 * The mac address returned is never a broadcast or multicast address!
 * @param __OUT__mac Pointer to netaddr_mac structure.
 */
void eth_rndaddr(struct netaddr_mac *mac);

#endif

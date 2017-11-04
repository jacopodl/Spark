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
 * @file datatype.h
 * @brief This file contains the data structures used by spark.
 */

#ifndef SPARK_DATATYPE_H
#define SPARK_DATATYPE_H

#define __NETADDR_BASE  struct {    \
    enum netaddr_type type;         \
    }

#define NETADDR_SET_TYPE(netaddr, tp)   netaddr.type=tp
#define NETADDR_SET_GENERIC(netaddr)    NETADDR_SET_TYPE(netaddr, NA_TYPE_GENERIC)
#define NETADDR_SET_MAC(netaddr)        NETADDR_SET_TYPE(netaddr, NA_TYPE_MAC)
#define NETADDR_SET_IP(netaddr)         NETADDR_SET_TYPE(netaddr, NA_TYPE_IP)
#define NETADDR_SET_IP6(netaddr)        NETADDR_SET_TYPE(netaddr, NA_TYPE_IP6)

#define NETADDR_GET_TYPE(netaddr)       netaddr.type
#define NETADDR_CMP_TYPE(netaddr, tp)   netaddr.type==tp

#ifdef __cplusplus
#define netaddr_generic(name)   struct netaddr_generic name{}; NETADDR_SET_GENERIC(name)
#define netaddr_mac(name)       struct netaddr_mac name{}; NETADDR_SET_MAC(name)
#define netaddr_ip(name)        struct netaddr_ip name{}; NETADDR_SET_IP(name)
#define netaddr_ip6(name)       struct netaddr_ip6 name{}; NETADDR_SET_IP6(name)
#else
#define netaddr_generic(name)   struct netaddr_generic name; NETADDR_SET_GENERIC(name)
#define netaddr_mac(name)       struct netaddr_mac name; NETADDR_SET_MAC(name)
#define netaddr_ip(name)        struct netaddr_ip name; NETADDR_SET_IP(name)
#define netaddr_ip6(name)       struct netaddr_ip6 name; NETADDR_SET_IP6(name)
#endif

enum netaddr_type {
    NA_TYPE_GENERIC,
    NA_TYPE_MAC,
    NA_TYPE_IP,
    NA_TYPE_IP6
};

struct netaddr {
    __NETADDR_BASE;
};

/// @brief Generic addresses container.
struct netaddr_generic {
    __NETADDR_BASE;
    /// @brief Generic address array.
    unsigned char na_data[22];
};

/**
 * @brief This structure contains MAC addresses.
 *
 * You can fill the structure in this way:
 * @code
 * struct netaddr_mac mac;
 * parse_hwaddr("A0:BB:CC:00:0E:1A",&mac,false);
 * @endcode
 */
struct netaddr_mac {
    __NETADDR_BASE;
    /// @brief Mac address array.
    unsigned char mac[6];
};

/**
 * @brief This structure contains IPv4 addresses.
 *
 * You can fill the structure in this way:
 * @code
 * struct netaddr_ip ip;
 * ip_parse_addr("192.168.1.254", &ip)
 * @endcode
 */
struct netaddr_ip {
    __NETADDR_BASE;
    /// @brief IpV4 integer.
    unsigned int ip;
};

/**
 * @brief This structure contains IPv6 addresses.
 */
struct netaddr_ip6 {
    __NETADDR_BASE;
    /// @brief IPv6 address array.
    unsigned char ip6[16];
};

#endif
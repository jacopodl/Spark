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
 * @file datatype.h
 * @brief This file contains the data structures used by spark.
 */

#ifndef SPARK_DATATYPE_H
#define SPARK_DATATYPE_H

/// @brief Generic addresses container.
struct netaddr {
	/// @brief Generic address array.
    unsigned char na_data[20];
};

/**
 * @brief This structure contains mac addresses.
 *
 * You can fill the structure in this way:
 * @code
 * struct netaddr_mac mac;
 * parse_hwaddr("A0:BB:CC:00:0E:1A",&mac,false);
 * @endcode
 */
struct netaddr_mac {
	/// @brief Mac address array.
    unsigned char mac[6];
};

/**
 * @brief This structure contains IpV4 addresses.
 *
 * You can fill the structure in this way:
 * @code
 * struct netaddr_ip ip;
 * parse_ipv4addr("192.168.1.254", &ip.ip)
 * @endcode
 */
struct netaddr_ip {
	/// @brief IpV4 integer.
    unsigned int ip;
};

#endif

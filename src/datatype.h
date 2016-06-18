/*
* <datatype, part of Spark.>
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

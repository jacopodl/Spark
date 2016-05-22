/*
* <routev4, part of Spark.>
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
 * @file routev4.h
 * @brief Provides useful functions for manage kernel IPv4 routing table.
 */

#ifndef SPARK_ROUTEV4_H
#define SPARK_ROUTEV4_H

#include <stdbool.h>
#include "datatype.h"

#define ROUTETABLE   "/proc/net/route"

/**
 * @brief Obtains the address of default gateway.
 * @param iface_name Interface name.
 * @param __OUT__gateway Pointer to netaddr_ip structure.
 * @return Function returns true if the gateway address has been obtained, false otherwise.
 */
bool get_defgateway(char *iface_name, struct netaddr_ip *gateway);

#endif

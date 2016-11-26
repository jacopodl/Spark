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

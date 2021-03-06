/*
 * Copyright (c) 2016 - 2018 Jacopo De Luca
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

#include <stdlib.h>

#include <ethernet.h>
#include <spkerr.h>
#include <netdevice.h>

int netdev_burnedin_mac(const char *iface_name, struct netaddr_mac *mac) {
    return SPKERR_ENOSUPPORT;
}

int netdev_get_defgateway(const char *iface_name, struct netaddr_ip *gateway) {
    return SPKERR_ENOSUPPORT;
}

int netdev_get_mac(const char *iface_name, struct netaddr_mac *mac) {
    return SPKERR_ENOSUPPORT;
}

int netdev_set_mac(const char *iface_name, const struct netaddr_mac *mac) {
    return SPKERR_ENOSUPPORT;
}

struct NetDevice *netdev_get_iflist(unsigned int filter) {
    return NULL;
}

inline void netdev_iflist_cleanup(struct NetDevice *NetDevice) {
    return;
}

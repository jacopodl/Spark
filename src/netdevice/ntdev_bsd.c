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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <net/if_dl.h>

#include <ethernet.h>
#include <spkerr.h>
#include <netdevice.h>

int netdev_burnedin_mac(char *iface_name, struct netaddr_mac *mac) {
    return SPKERR_ENOSUPPORT;
}

int netdev_get_defgateway(char *iface_name, struct netaddr_ip *gateway) {
    return SPKERR_ENOSUPPORT;
}

int netdev_get_mac(char *iface_name, struct netaddr_mac *mac) {
    struct ifaddrs *ifa;
    struct ifaddrs *curr;
    struct sockaddr_dl *sdl;
    int error = SPKERR_ERROR;

    if (getifaddrs(&ifa) < 0)
        return SPKERR_ERROR;

    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (strcmp(curr->ifa_name, iface_name) == 0) {
            if (curr->ifa_addr != NULL && curr->ifa_addr->sa_family == AF_LINK) {
                sdl = (struct sockaddr_dl *) curr->ifa_addr;
                switch (sdl->sdl_alen) {
                    case 0:
                        if ((curr->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
                            memset(mac->mac, 0x00, ETHHWASIZE);
                            error = SPKERR_SUCCESS;
                            break;
                        }
                        error = SPKERR_ERROR;
                        break;
                    case ETHHWASIZE:
                        memcpy(mac->mac, LLADDR(sdl), sdl->sdl_alen);
                        error = SPKERR_SUCCESS;
                        break;
                    default:
                        error = SPKERR_ERROR;
                }
                freeifaddrs(ifa);
                return error;
            }
        }
    }
    freeifaddrs(ifa);
    return SPKERR_ERROR;
}

int netdev_set_mac(char *iface_name, struct netaddr_mac *mac) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = SPKERR_ERROR;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        memcpy(&req.ifr_addr.sa_data, mac->mac, ETHHWASIZE);
        req.ifr_addr.sa_len = ETHHWASIZE;
        if (ioctl(ctl_sock, SIOCSIFLLADDR, &req) >= 0)
            ret = SPKERR_SUCCESS;
        close(ctl_sock);
    }
    return ret;
}

struct NetDevice *netdev_get_iflist(unsigned int filter) {
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *curr = NULL;
    struct sockaddr_dl *sdl = NULL;
    struct NetDevice *devs = NULL;
    struct NetDevice *dev = NULL;

    if (getifaddrs(&ifa) < 0)
        return SPKERR_ERROR;

    filter = (filter == 0 ? ~filter : filter);
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (curr->ifa_addr->sa_family != AF_LINK)
            continue;
        if (!(curr->ifa_flags & filter))
            continue;
        if ((dev = (struct NetDevice *) malloc(sizeof(struct NetDevice))) == NULL) {
            netdev_iflist_cleanup(devs);
            return NULL;
        }
        memcpy(dev->name, curr->ifa_name, IFNAMSIZ);
        dev->flags = curr->ifa_flags;
        sdl = (struct sockaddr_dl *) curr->ifa_addr;
        if (sdl->sdl_alen == ETHHWASIZE)
            memcpy(dev->mac.mac, LLADDR(sdl), ETHHWASIZE);
        dev->next = devs;
        devs = dev;
    }
    freeifaddrs(ifa);
    return devs;
}
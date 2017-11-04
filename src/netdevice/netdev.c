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
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>

#include <spkerr.h>
#include <netdevice.h>

int netdev_get_flags(char *iface_name, short *flags) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = SPKERR_ERROR;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFFLAGS, &req) >= 0) {
            *flags = req.ifr_flags;
            ret = SPKERR_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

int netdev_get_ip(char *iface_name, struct netaddr_ip *ip) {
    int ret = SPKERR_ERROR;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_addr.sa_family = AF_INET;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFADDR, &req) >= 0) {
            ip->ip = ((struct sockaddr_in *) &req.ifr_addr)->sin_addr.s_addr;
            ret = SPKERR_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

int netdev_get_mtu(char *iface_name) {
    int ret = SPKERR_ERROR;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_addr.sa_family = AF_INET;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFMTU, &req) >= 0)
            ret = req.ifr_mtu;
        close(ctl_sock);
    }
    return ret;
}

int netdev_get_netmask(char *iface_name, struct netaddr_ip *netmask) {
    int ret = SPKERR_ERROR;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_addr.sa_family = AF_INET;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFNETMASK, &req) >= 0) {
            netmask->ip = ((struct sockaddr_in *) &req.ifr_addr)->sin_addr.s_addr;
            ret = SPKERR_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

int netdev_set_flags(char *iface_name, short flags) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_flags = flags;

    ret = SPKERR_ERROR;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCSIFFLAGS, &req) >= 0)
            ret = SPKERR_SUCCESS;
        close(ctl_sock);
    }
    return ret;
}

int netdev_set_mtu(char *iface_name, int mtu) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_mtu = mtu;

    ret = SPKERR_ERROR;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCSIFMTU, &req) >= 0)
            ret = SPKERR_SUCCESS;
        close(ctl_sock);
    }
    return ret;
}

inline void netdev_iflist_cleanup(struct NetDevice *NetDevice) {
    struct NetDevice *tmp, *curr;
    for (curr = NetDevice; curr != NULL; tmp = curr->next, free(curr), curr = tmp);
}
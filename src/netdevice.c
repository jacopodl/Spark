/*
* netdevice, part of Spark.
* Copyright (C) 2015-2016 Jacopo De Luca
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>

#ifdef __linux__

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#include <net/if_dl.h>
#endif

#include "netdevice.h"
#include "ethernet.h"

#if defined(__linux__)

int get_device_burnedin_mac(char *iface_name, struct netaddr_mac *mac) {

    /* struct ethtool_perm_addr{
        __u32   cmd;
        __u32   size;
        __u8    data[0];}
    */

    int ret;
    int ctl_sock;
    struct ifreq req;
    struct ethtool_perm_addr *epa;

    memset(mac, 0x00, sizeof(struct netaddr_mac));
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);

    if ((epa = (struct ethtool_perm_addr *) malloc(sizeof(struct ethtool_perm_addr) + ETHHWASIZE)) == NULL)
        return NETD_UNSUCCESS;

    epa->cmd = ETHTOOL_GPERMADDR;
    epa->size = ETHHWASIZE;
    req.ifr_data = (caddr_t) epa;

    ret = NETD_UNSUCCESS;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if ((ioctl(ctl_sock, SIOCETHTOOL, &req) >= 0)) {
            memcpy(mac->mac, epa->data, ETHHWASIZE);
            ret = NETD_SUCCESS;
        }
        close(ctl_sock);
    }
    free(epa);
    return ret;
}

#else
#pragma message("get_device_burnedin_mac not supported on OS! :( ")
int get_device_burnedin_mac(char *iface_name, struct netaddr_mac *mac){
    // Stub
    return NETD_NOTSUPPORTED;
}
#endif

int get_device_flags(char *iface_name, short *flags) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = NETD_UNSUCCESS;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFFLAGS, &req) >= 0) {
            *flags = req.ifr_flags;
            ret = NETD_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

#if defined(__linux__)

int get_device_mac(char *iface_name, struct netaddr_mac *mac) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = NETD_UNSUCCESS;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFHWADDR, &req) >= 0) {
            memcpy(mac->mac, &req.ifr_hwaddr.sa_data, ETHHWASIZE);
            ret = NETD_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
int get_device_mac(char *iface_name, struct netaddr_mac *mac) {
    bool success = NETD_UNSUCCESS;
    struct ifaddrs *ifa = NULL, *curr = NULL;
    if (getifaddrs(&ifa) < 0)
        return NETD_UNSUCCESS;
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (strcmp(curr->ifa_name, iface_name) == 0 && curr->ifa_addr != NULL && curr->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *) curr->ifa_addr;
            if (sdl->sdl_alen == ETHHWASIZE) {
                memcpy(mac->mac, LLADDR(sdl), sdl->sdl_alen);
                success = NETD_SUCCESS;
                break;
            }
        }
    }
    freeifaddrs(ifa);
    return success;
}
#endif

int get_iflist(unsigned int filter, struct ifList **iflist) {
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *curr = NULL;
    struct ifList *tmp = NULL;

    if (getifaddrs(&ifa) < 0)
        return NETD_UNSUCCESS;

    filter = (filter == 0 ? ~filter : filter);
    *iflist = NULL;
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
#if defined(__linux__)
        if (curr->ifa_addr->sa_family != AF_PACKET)
            continue;
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
        if (curr->ifa_addr->sa_family != AF_LINK)
            continue;
#endif
        if (!(curr->ifa_flags & filter))
            continue;
        if ((tmp = (struct ifList *) malloc(sizeof(struct ifList))) == NULL) {
            iflist_cleanup(*iflist);
            return NETD_UNSUCCESS;
        }
        memcpy(tmp->name, curr->ifa_name, IFNAMSIZ);
        tmp->flags = curr->ifa_flags;
#if defined(__linux__)
        struct sockaddr_ll *sll = (struct sockaddr_ll *) curr->ifa_addr;
        memcpy(tmp->mac.mac, sll->sll_addr, ETHHWASIZE);
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
        struct sockaddr_dl *sdl = (struct sockaddr_dl *) curr->ifa_addr;
        if (sdl->sdl_alen == ETHHWASIZE)
            memcpy(tmp->mac.mac, LLADDR(sdl), sdl->sdl_alen);
#endif
        tmp->next = *iflist;
        *iflist = tmp;
    }
    freeifaddrs(ifa);
    return NETD_SUCCESS;
}

int set_device_flags(char *iface_name, short flags) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_flags = flags;

    ret = NETD_UNSUCCESS;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCSIFFLAGS, &req) >= 0)
            ret = NETD_SUCCESS;
        close(ctl_sock);
    }
    return ret;
}

int set_device_mac(char *iface_name, struct netaddr_mac *mac) {
    /*
     * Set the hardware address of a device using ifr_hwaddr.
     * The hardware address is specified in a struct sockaddr.
     * sa_family contains the ARPHRD_* device type, sa_data the L2
     * hardware address starting from byte 0.
     */
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = NETD_UNSUCCESS;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
#if defined(__linux__)
        memcpy(&req.ifr_hwaddr.sa_data, mac->mac, ETHHWASIZE);
        req.ifr_hwaddr.sa_family = (unsigned short) 0x01;
        if (ioctl(ctl_sock, SIOCSIFHWADDR, &req) >= 0)
            ret = NETD_SUCCESS;
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
        memcpy(&req.ifr_addr.sa_data, mac->mac, ETHHWASIZE);
        req.ifr_addr.sa_len = ETHHWASIZE;
        if (ioctl(ctl_sock, SIOCSIFLLADDR, &req) >= 0)
            ret = NETD_SUCCESS;
#endif
        close(ctl_sock);
    }
    return ret;
}

inline void iflist_cleanup(struct ifList *ifList) {
    struct ifList *tmp, *curr;
    for (curr = ifList; curr != NULL; tmp = curr->next, free(curr), curr = tmp);
}
/*
* <netdevice, part of Spark.>
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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <errno.h>
#include <unistd.h>

#include "netdevice.h"
#include "ethernet.h"

#ifdef __linux__

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#include <net/if_dl.h>
#include <net/bpf.h>
#include <fcntl.h>
#endif

#if defined(__linux__)

int get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa) {

    /* struct ethtool_perm_addr{
        __u32   cmd;
        __u32   size;
        __u8    data[0];}
    */

    struct ifreq req;
    struct ethtool_perm_addr *epa;

    if ((epa = (struct ethtool_perm_addr *) malloc(sizeof(struct ethtool_perm_addr) + ETHHWASIZE)) == NULL)
        return NETD_UNSUCCESS;
    epa->cmd = ETHTOOL_GPERMADDR;
    epa->size = ETHHWASIZE;

    memset(hwa, 0x00, sizeof(struct sockaddr));
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_data = (caddr_t) epa;

    if ((ioctl(sd, SIOCETHTOOL, &req) < 0)) {
        free(epa);
        return NETD_UNSUCCESS;
    }
    else
        memcpy(hwa->sa_data, epa->data, ETHHWASIZE);
    free(epa);
    return NETD_SUCCESS;
}

#else
#pragma message("get_burnedin_mac not supported on OS! :( ")
int get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa){
    // Stub
    return NETD_NOTSUPPORTED;
}
#endif

int get_flags(int sd, char *iface_name, short *flags) {
    /* Get the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    if (ioctl(sd, SIOCGIFFLAGS, &req) < 0)
        return NETD_UNSUCCESS;
    *flags = req.ifr_flags;
    return NETD_SUCCESS;
}

#if defined(__linux__)

int get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    /* Get the hardware address of a device using ifr_hwaddr. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    if (ioctl(sd, SIOCGIFHWADDR, &req) < 0)
        return NETD_UNSUCCESS;
    memcpy(hwaddr, &req.ifr_hwaddr, sizeof(struct sockaddr));
    return NETD_SUCCESS;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
int get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    bool success = NETD_UNSUCCESS;
    struct ifaddrs *ifa = NULL, *curr = NULL;
    if (getifaddrs(&ifa) < 0)
        return NETD_UNSUCCESS;
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (strcmp(curr->ifa_name, iface_name) == 0 && curr->ifa_addr != NULL && curr->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *) curr->ifa_addr;
            if (sdl->sdl_alen == ETHHWASIZE) {
                memcpy(hwaddr->sa_data, LLADDR(sdl), sdl->sdl_alen);
                success = NETD_SUCCESS;
                break;
            }
        }
    }
    freeifaddrs(ifa);
    return success;
}
#endif


int llclose(struct llOptions *llo, bool freemem) {
    int ret;
    if ((ret = close(llo->sfd)) < 0)
        return -1;
    if (freemem)
        free(llo);
    else
        llo->sfd = -1;
    return ret;
}

#if defined(__linux__)

int llsocket(struct llOptions *llo) {
    int sock;
    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_halen = ETHHWASIZE;
    sll.sll_protocol = htons(ETH_P_ALL);
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        return -1;
    if ((sll.sll_ifindex = if_nametoindex(llo->iface_name)) == 0) {
        close(sock);
        return -1;
    }
    if (bind(sock, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) < 0) {
        close(sock);
        return -1;
    }
    llo->sfd = sock;
    if (llo->buffl == 0)
        llo->buffl = sizeof(struct EthHeader) + ETHMAXPAYL; // Size of 1 packet
    return sock;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
int llsocket(struct llOptions *llo) {
    int sock = -1, var;
    for (int i = 0; i < BPFMAXDEV; i++) {
        sprintf(llo->bsd_bind, "/dev/bpf%i", i);
        if ((sock = open(llo->bsd_bind, O_RDWR)) != -1)
            break;
    }
    if (sock == -1) {
        errno = ENODEV;
        return -1;
    }
    struct ifreq bound_if;
    memset(&bound_if, 0x00, sizeof(struct ifreq));
    strcpy(bound_if.ifr_name, llo->iface_name);
    if (llo->buffl == 0) {
        if (ioctl(sock, BIOCGBLEN, &llo->buffl) < 0) {
            close(sock);
            return -1;
        }
    }
    else {
        if (ioctl(sock, BIOCSBLEN, &llo->buffl) < 0) {
            close(sock);
            return -1;
        }
    }
    if (ioctl(sock, BIOCSETIF, &bound_if) < 0) {
        close(sock);
        return -1;
    }
    var = 1;
    if (ioctl(sock, BIOCIMMEDIATE, &var) < 0) {
        close(sock);
        return -1;
    }
    llo->sfd = sock;
    return sock;
}

#endif

struct ifList *get_iflist(unsigned int filter) {
    struct ifList *iflist = NULL;
    struct ifaddrs *ifa = NULL, *curr = NULL;
    if (getifaddrs(&ifa) < 0)
        return NULL;
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
#if defined(__linux__)
        if (curr->ifa_addr->sa_family != AF_PACKET)
            continue;
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
        if (curr->ifa_addr->sa_family != AF_LINK)
            continue;
#endif
        if ((curr->ifa_flags & filter) != filter || (curr->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
            continue;
        struct ifList *tmp = (struct ifList *) malloc(sizeof(struct ifList));
        if (tmp == NULL) {
            iflist_cleanup(iflist);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(tmp->name, curr->ifa_name, IFNAMSIZ);
        tmp->next = iflist;
        iflist = tmp;
    }
    freeifaddrs(ifa);
    return iflist;
}

inline void iflist_cleanup(struct ifList *ifList) {
    struct ifList *tmp, *curr;
    for (curr = ifList; curr != NULL; tmp = curr->next, free(curr), curr = tmp);
}

int set_flags(int sd, char *iface_name, short flags) {
    /* Set the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_flags = flags;
    return ioctl(sd, SIOCSIFFLAGS, &req) != -1 ? NETD_SUCCESS : NETD_UNSUCCESS;
}

#if defined(__linux__)

int set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    /*
     * Set the hardware address of a device using ifr_hwaddr.
     * The hardware address is specified in a struct sockaddr.
     * sa_family contains the ARPHRD_* device type, sa_data the L2
     * hardware address starting from byte 0.
     */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    memcpy(&req.ifr_hwaddr.sa_data, hwaddr->sa_data, ETHHWASIZE);
    req.ifr_hwaddr.sa_family = (unsigned short) 0x01;
    return ioctl(sd, SIOCSIFHWADDR, &req) != -1 ? NETD_SUCCESS : NETD_UNSUCCESS;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
int set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    memcpy(&req.ifr_addr.sa_data, hwaddr->sa_data, ETHHWASIZE);
    req.ifr_addr.sa_len = ETHHWASIZE;
    return ioctl(sd, SIOCSIFLLADDR, &req) != -1?NETD_SUCCESS:NETD_UNSUCCESS;
}

#endif

inline ssize_t llrecv(void *buff, struct llOptions *llo) {
    return read(llo->sfd, buff, llo->buffl);
}

inline ssize_t llsend(const void *buff, unsigned long len, struct llOptions *llo) {
    return write(llo->sfd, buff, len == 0 ? llo->buffl : len);
}

inline void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl) {
    memset(llo, 0x00, sizeof(struct llOptions));
    memcpy(llo->iface_name, iface_name, IFNAMSIZ);
    llo->buffl = buffl;
}
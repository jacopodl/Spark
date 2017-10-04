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
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>

#include <ethernet.h>
#include <spkerr.h>
#include <netdevice.h>

int netdev_burnedin_mac(char *iface_name, struct netaddr_mac *mac) {

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
        return SPKERR_ERROR;

    epa->cmd = ETHTOOL_GPERMADDR;
    epa->size = ETHHWASIZE;
    req.ifr_data = (caddr_t) epa;

    ret = SPKERR_ERROR;
    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if ((ioctl(ctl_sock, SIOCETHTOOL, &req) >= 0)) {
            memcpy(mac->mac, epa->data, ETHHWASIZE);
            ret = SPKERR_SUCCESS;
        }
        close(ctl_sock);
    }
    free(epa);
    return ret;
}

int netdev_get_defgateway(char *iface_name, struct netaddr_ip *gateway) {
    char buf[1024];
    char ifa[24];
    int dest;
    unsigned int gate;
    int flags;
    int fd;
    char *line;

    if ((fd = open(ROUTETABLE, O_RDONLY)) < 0)
        return SPKERR_ERROR;

    while (read(fd, buf, 1024) != 0) {
        line = strtok(buf, "\n");
        while (line != NULL) {
            if (sscanf(line, "%s\t%u\t%x\t%u", ifa, &dest, &gate, &flags) != 4) {
                line = strtok(NULL, "\n");
                continue;
            }
            if (iface_name != NULL && strcmp(iface_name, ifa) != 0) {
                line = strtok(NULL, "\n");
                continue;
            }
            if (dest != 0 && flags < 2) {
                line = strtok(NULL, "\n");
                continue;
            }
            gateway->ip = gate;
            close(fd);
            return SPKERR_SUCCESS;
        }
    }

    close(fd);
    return SPKERR_ERROR;
}

int netdev_get_mac(char *iface_name, struct netaddr_mac *mac) {
    int ret;
    int ctl_sock;
    struct ifreq req;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    ret = SPKERR_ERROR;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(ctl_sock, SIOCGIFHWADDR, &req) >= 0) {
            memcpy(mac->mac, &req.ifr_hwaddr.sa_data, ETHHWASIZE);
            ret = SPKERR_SUCCESS;
        }
        close(ctl_sock);
    }
    return ret;
}

int netdev_set_mac(char *iface_name, struct netaddr_mac *mac) {
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
    ret = SPKERR_ERROR;

    if ((ctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        memcpy(&req.ifr_hwaddr.sa_data, mac->mac, ETHHWASIZE);
        req.ifr_hwaddr.sa_family = (unsigned short) 0x01;
        if (ioctl(ctl_sock, SIOCSIFHWADDR, &req) >= 0)
            ret = SPKERR_SUCCESS;
        close(ctl_sock);
    }
    return ret;
}

struct NetDevice *netdev_get_iflist(unsigned int filter) {
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *curr = NULL;
    struct NetDevice *devs = NULL;
    struct NetDevice *dev = NULL;
    struct sockaddr_ll *sll = NULL;

    if (getifaddrs(&ifa) < 0)
        return NULL;

    filter = (filter == 0 ? ~filter : filter);
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (curr->ifa_addr->sa_family != AF_PACKET)
            continue;
        if (!(curr->ifa_flags & filter))
            continue;
        if ((dev = (struct NetDevice *) malloc(sizeof(struct NetDevice))) == NULL) {
            netdev_iflist_cleanup(devs);
            return NULL;
        }
        memcpy(dev->name, curr->ifa_name, IFNAMSIZ);
        dev->flags = curr->ifa_flags;
        sll = (struct sockaddr_ll *) curr->ifa_addr;
        memcpy(dev->mac.mac, sll->sll_addr, ETHHWASIZE);
        dev->next = devs;
        devs = dev;
    }
    freeifaddrs(ifa);
    return devs;
}
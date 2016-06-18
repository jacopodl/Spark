/*
* llsock, part of Spark.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>

#include "llsock.h"
#include "netdevice.h"

#if defined(__linux__)

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#include <stdio.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#endif

int llclose(struct llSockInfo *llsi, bool freemem) {
    int ret;
    if ((ret = close(llsi->sfd)) > 0) {
        memset(llsi, 0x00, sizeof(struct llSockInfo));
        if (freemem)
            free(llsi);
    }
    return ret;
}

#if defined(__linux__)

int llsocket(struct llSockInfo *llsi, char *iface_name, unsigned int buffl) {
    int sock;
    struct sockaddr_ll sll;

    if (buffl != 0 && buffl < LLSOCK_DEFRBUF) {
        errno = EINVAL;
        return -1;
    }

    memset(llsi, 0x00, sizeof(struct llSockInfo));
    memcpy(llsi->iface_name, iface_name, IFNAMSIZ);

    sll.sll_family = AF_PACKET;
    sll.sll_halen = ETHHWASIZE;
    sll.sll_protocol = htons(ETH_P_ALL);

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) >= 0) {
        if ((sll.sll_ifindex = if_nametoindex(llsi->iface_name)) > 0) {
            if (get_device_mac(llsi->iface_name, &llsi->iface_mac) == NETD_SUCCESS) {
                if (bind(sock, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) >= 0) {
                    llsi->sfd = sock;
                    if (buffl == 0)
                        llsi->buffl = LLSOCK_DEFRBUF; // Size of 1 Ethernet packet
                    else
                        llsi->buffl = buffl;
                    return sock;
                }
            }
        }
    }
    return -1;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
int llsocket(struct llSockInfo *llsi, char *iface_name, unsigned int buffl) {
    int sock = -1;
    int var;
    struct ifreq bound_if;

    if (buffl != 0 && buffl < LLSOCK_DEFRBUF) {
        errno = EINVAL;
        return -1;
    }

    memset(&bound_if, 0x00, sizeof(struct ifreq));
    strcpy(bound_if.ifr_name, llsi->iface_name);

    for (int i = 0; i < LLSOCK_BPFMAXDEV; i++) {
        sprintf(llsi->bpf_path, "/dev/bpf%i", i);
        if ((sock = open(llsi->bpf_path, O_RDWR)) >= 0) {
            if (llsi->buffl == 0) {
                if (ioctl(sock, BIOCGBLEN, &llsi->buffl) < 0) {
                    close(sock);
                    return -1;
                }
            }
            else {
                if (ioctl(sock, BIOCSBLEN, &llsi->buffl) < 0) {
                    close(sock);
                    return -1;
                }
            }
            if (ioctl(sock, BIOCSETIF, &bound_if) >= 0) {
                var = 1;
                if (ioctl(sock, BIOCIMMEDIATE, &var) >= 0) {
                    if (get_device_mac(llsi->iface_name, &llsi->iface_mac) == NETD_SUCCESS) {
                        llsi->sfd = sock;
                        return sock;
                    }
                }
            }
            close(sock);
            return -1;
        }
    }
    errno = ENODEV;
    return -1;
}

#endif

inline ssize_t llrecv2(void *buff, struct llSockInfo *llsi) {
    return read(llsi->sfd, buff, llsi->buffl);
}

inline ssize_t llrecv3(void *buff, unsigned long len, struct llSockInfo *llsi) {
    return read(llsi->sfd, buff, len);
}

inline ssize_t llsend(const void *buff, unsigned long len, struct llSockInfo *llsi) {
    return write(llsi->sfd, buff, len == 0 ? llsi->buffl : len);
}
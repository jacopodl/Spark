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

#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <ethernet.h>
#include "spksock_common.h"
#include "spksock_linux.h"

static bool __linux_discards_direction(struct SpkSock *ssock, struct sockaddr_ll *sll) {
    if (ssock->direction == SPKDIR_BOTH)
        return false;

    if (sll->sll_pkttype == PACKET_OUTGOING)
        return ssock->direction == SPKDIR_IN;

    // Incoming packet
    if (ssock->direction == SPKDIR_OUT)
        return true;

    return false;
}

static int spksock_linux_read(struct SpkSock *ssock, unsigned char *buf, struct SpkTimeStamp *ts) {
    struct sockaddr_ll from;
    struct timeval tval;
    struct timespec tspec;
    unsigned int pkt_len = 0;
    unsigned int flen = 0;

    do {
        pkt_len = (unsigned int) recvfrom(ssock->sfd, buf, ssock->bufl, MSG_TRUNC, (struct sockaddr *) &from, &flen);
        if (pkt_len == -1) {
            switch (errno) {
                case EAGAIN:
                    return 0;
                case EINTR:
                    return SPKERR_EINTR;
                default:
                    return SPKERR_ERROR;
            }
        }
    } while (__linux_discards_direction(ssock, &from));

    ssock->sock_stats.rx_byte += pkt_len;
    ssock->sock_stats.pkt_recv++;

    if (ts != NULL) {
        if (ssock->tsprc == SPKSTAMP_MICRO) {
            ioctl(ssock->sfd, SIOCGSTAMP, &tval);
            ts->sec = tval.tv_sec;
            ts->subs = tval.tv_usec;
        } else {
            ioctl(ssock->sfd, SIOCGSTAMPNS, &tspec);
            ts->sec = tspec.tv_sec;
            ts->subs = tspec.tv_nsec;
        }
        ts->prc = ssock->tsprc;
    }

    return pkt_len;
}

static int spksock_linux_setdir(struct SpkSock *ssock, enum SpkDirection direction) {
    ssock->direction = direction;
    return SPKERR_SUCCESS;
}

static int spksock_linux_setnblock(struct SpkSock *ssock, bool nonblock) {
    int flags;
    if (nonblock)
        flags = O_NONBLOCK;
    else {
        flags = fcntl(ssock->sfd, F_GETFL, 0);
        flags ^= O_NONBLOCK;
    }
    if (fcntl(ssock->sfd, F_SETFL, flags) < 0)
        return SPKERR_ERROR;
    return SPKERR_SUCCESS;
}

static int spksock_linux_setprc(struct SpkSock *ssock, enum SpkTimesPrc prc) {
    ssock->tsprc = prc;
    return SPKERR_SUCCESS;
}

static int spksock_linux_setpromisc(struct SpkSock *ssock, bool promisc) {
    struct packet_mreq pm;

    memset(&pm, 0x00, sizeof(struct packet_mreq));
    pm.mr_ifindex = __linux_get_ifindex(ssock);
    pm.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(ssock->sfd, SOL_PACKET, promisc ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP, &pm,
                   sizeof(struct packet_mreq)) < 0) {
        return SPKERR_ERROR;
    }

    return SPKERR_SUCCESS;
}

static int spksock_linux_write(struct SpkSock *ssock, unsigned char *buf, unsigned int len) {
    int byte;

    if ((byte = (int) write(ssock->sfd, buf, len)) > 0) {
        ssock->sock_stats.tx_byte += byte;
        ssock->sock_stats.pkt_send++;
    }

    if (byte < 0) {
        switch (errno) {
            case EMSGSIZE:
                return SPKERR_ESIZE;
            case EINTR:
                return SPKERR_EINTR;
            default:
                return SPKERR_ERROR;
        }
    }

    return byte;
}

static int __linux_get_ifindex(struct SpkSock *ssock) {
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, ssock->iface_name);

    if (ioctl(ssock->sfd, SIOCGIFINDEX, &ifr) < 0)
        return -1;

    return ifr.ifr_ifindex;
}

int __ssock_init_socket(struct SpkSock *ssock) {
    struct sockaddr_ll sll;
    struct ifreq ifr;

    if ((ssock->sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        switch (errno) {
            case EACCES:
            case EPERM:
                return SPKERR_EPERM;
            case ENOBUFS:
            case ENOMEM:
                return SPKERR_ENOMEM;
            default:
                return SPKERR_ERROR;
        }
    }

    memset(&sll, 0x00, sizeof(struct sockaddr_ll));
    memset(&ifr, 0x00, sizeof(struct ifreq));

    strcpy(ifr.ifr_name, ssock->iface_name);

    // IFACE BIND
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = __linux_get_ifindex(ssock);
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(ssock->sfd, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) < 0) {
        close(ssock->sfd);
        return SPKERR_ENODEV;
    }

    if (ioctl(ssock->sfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(ssock->sfd);
        return SPKERR_ERROR;
    }

    __linux_map_dlt(ssock, ifr.ifr_hwaddr.sa_family);

    memcpy(ssock->iaddr.mac, ifr.ifr_hwaddr.sa_data, ETHHWASIZE);
    ssock->direction = SPKDIR_BOTH;
    ssock->tsprc = SPKSTAMP_MICRO;
    ssock->op.finalize = spksock_linux_finalize;
    ssock->op.read = spksock_linux_read;
    ssock->op.setdir = spksock_linux_setdir;
    ssock->op.setnblk = spksock_linux_setnblock;
    ssock->op.setprc = spksock_linux_setprc;
    ssock->op.setpromisc = spksock_linux_setpromisc;
    ssock->op.write = spksock_linux_write;

    return SPKERR_SUCCESS;
}

static void spksock_linux_finalize(struct SpkSock *ssock) {
    close(ssock->sfd);
}

static void __linux_map_dlt(struct SpkSock *ssock, int arphdr) {
    switch (arphdr) {
        case ARPHRD_ETHER:
        case ARPHRD_METRICOM:
        case ARPHRD_LOOPBACK:
            ssock->lktype = DLT_EN10MB;
            break;
        case ARPHRD_EETHER:
            ssock->lktype = DLT_EN3MB;
            break;
        case ARPHRD_PRONET:
            ssock->lktype = DLT_PRONET;
            break;
        case ARPHRD_CHAOS:
            ssock->lktype = DLT_CHAOS;
            break;
        case ARPHRD_FDDI:
            ssock->lktype = DLT_FDDI;
            break;
        case ARPHRD_IEEE802_TR:
        case ARPHRD_IEEE802:
            ssock->lktype = DLT_IEEE802;
            break;
        case ARPHRD_IEEE80211:
            ssock->lktype = DLT_IEEE802_11;
            break;
        case ARPHRD_IEEE80211_RADIOTAP:
            ssock->lktype = DLT_IEEE802_11_RADIO;
            break;
        case ARPHRD_IEEE80211_PRISM:
            ssock->lktype = DLT_PRISM_HEADER;
            break;
        case ARPHRD_IEEE802154:
            ssock->lktype = DLT_IEEE802_15_4_NOFCS;
            break;
        case ARPHRD_NONE:
            ssock->lktype = DLT_RAW;
            break;
        default:
            ssock->lktype = -1;
            break;
    }
}

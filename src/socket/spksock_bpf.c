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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/bpf.h>
#include <ifaddrs.h>

#include <ethernet.h>
#include "spksock_common.h"
#include "spksock_bpf.h"

static int spksock_bpf_read(struct SpkSock *ssock, unsigned char *buf, struct SpkTimeStamp *ts) {
    struct SpkBpf *priv = (struct SpkBpf *) ssock->aux;
    struct bpf_hdr *bhdr;

    if (priv->cursor >= priv->buf + priv->caplen) {
        if ((priv->caplen = read(ssock->sfd, priv->buf, priv->buflen)) < 0) {
            priv->caplen = 0;
            switch (errno) {
                case EAGAIN:
                    return 0;
                case EINTR:
                    return SPKERR_EINTR;
                default:
                    return SPKERR_ERROR;
            }
        }
        priv->cursor = priv->buf;
    }

    bhdr = (struct bpf_hdr *) priv->cursor;

    if (bhdr->bh_datalen < ssock->bufl)
        memcpy(buf, priv->cursor + bhdr->bh_hdrlen, bhdr->bh_datalen);
    else
        memcpy(buf, priv->cursor + bhdr->bh_hdrlen, ssock->bufl);

    if (ts != NULL) {
        ts->sec = bhdr->bh_tstamp.tv_sec;
        ts->subs = bhdr->bh_tstamp.tv_usec;
        ts->prc = ssock->tsprc;
    }
    ssock->sock_stats.rx_byte += bhdr->bh_datalen;
    ssock->sock_stats.pkt_recv++;
    priv->cursor += BPF_WORDALIGN(bhdr->bh_hdrlen + bhdr->bh_caplen);
    return bhdr->bh_datalen;
}

static int spksock_bpf_setdir(struct SpkSock *ssock, enum SpkDirection direction) {
    unsigned int bpfdir;
#ifdef BIOCSDIRECTION
    switch (direction) {
        case SPKDIR_IN:
            bpfdir = BPF_D_IN;
            break;
        case SPKDIR_OUT:
            bpfdir = BPF_D_OUT;
            break;
        default:
            bpfdir = BPF_D_INOUT;
    }
    if (ioctl(ssock->sfd, BIOCSDIRECTION, &bpfdir) < 0)
        return SPKERR_ERROR;
    ssock->direction = direction;
    return SPKERR_SUCCESS;
#elif defined(BIOCSSEESENT)
    switch (direction) {
            case SPKDIR_IN:
                bpfdir = 0;
                break;
            case SPKDIR_OUT:
                return SPKERR_ENOSUPPORT;
            default:
                bpfdir = 1;
        }
    if (ioctl(ssock->sfd, BIOCSSEESENT, &bpfdir) < 0)
            return SPKERR_ERROR;
    ssock->direction = direction;
    return SPKERR_SUCCESS;
#endif
}

static int spksock_bpf_setnblock(struct SpkSock *ssock, bool nonblock) {
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

static int spksock_bpf_setprc(struct SpkSock *ssock, enum SpkTimesPrc prc) {
#ifdef BIOCSTSTAMP
    unsigned int bpfprc;

    if (prc == SPKSTAMP_MICRO)
        bpfprc = BPF_T_MICROTIME;
    else
        bpfprc = BPF_T_NANOTIME;
    if (ioctl(ssock->sfd, BIOCSTSTAMP, &bpfprc) < 0)
        return SPKERR_ERROR;
    ssock->tsprc = prc;
    return SPKERR_SUCCESS;
#else
    return SPKERR_ENOSUPPORT;
#endif
}

static int spksock_bpf_setpromisc(struct SpkSock *ssock, bool promisc) {
    struct SpkBpf *priv = (struct SpkSock *) ssock->aux;
    struct ifreq req;
    int flags;

    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, ssock->iface_name);

    if (ioctl(priv->sock, SIOCGIFFLAGS, &req) < 0)
        return SPKERR_ERROR;
#if defined (__FreeBSD__)
    flags = (req.ifr_flags & 0xffff) | (req.ifr_flagshigh << 16);

    if (promisc)
        flags |= IFF_PPROMISC;
    else
        flags &= ~IFF_PPROMISC;

    req.ifr_flags = flags & 0xffff;
    req.ifr_flagshigh = flags >> 16;
#else
    if (promisc)
        req.ifr_flags = (req.ifr_flags | IFF_PROMISC);
    else
        req.ifr_flags &= ~IFF_PROMISC;
#endif
    if (ioctl(priv->sock, SIOCSIFFLAGS, &req) < 0)
        return SPKERR_ERROR;
    return SPKERR_SUCCESS;
}

static int spksock_bpf_write(struct SpkSock *ssock, unsigned char *buf, unsigned int len) {
    int byte;

    if ((byte = (int) write(ssock->sfd, buf, len)) > 0) {
        ssock->sock_stats.tx_byte += byte;
        ssock->sock_stats.pkt_send++;
    }

    if (byte < 0) {
        switch (errno) {
            case EINTR:
                return SPKERR_EINTR;
            default:
                return SPKERR_ERROR;
        }
    }

    return byte;
}

int __ssock_init_socket(struct SpkSock *ssock) {
    char bpf_file[SPKBPF_MAXPATHLEN];
    struct ifreq ifr;
    struct SpkBpf *priv;
    int var = 1;

    for (int i = 0; i < SPKBPF_MAXDEV; i++) {
        sprintf(bpf_file, "/dev/bpf%i", i);

        if ((ssock->sfd = open(bpf_file, O_RDWR)) < 0) {
            switch (errno) {
                case EACCES:
                    return SPKERR_EPERM;
                case ENOMEM:
                    return SPKERR_ENOMEM;
                case EBUSY:
                    break;
                default:
                    return SPKERR_ERROR;
            }
        }

        if (ssock->sfd >= 0) {
            memset(&ifr, 0x00, sizeof(struct ifreq));
            strcpy(ifr.ifr_name, ssock->iface_name);

            // IFACE BIND
            if (ioctl(ssock->sfd, BIOCSETIF, &ifr) < 0)
                break;

            if (__bpf_get_hwaddr(ssock) != SPKERR_SUCCESS)
                break;

            if (ioctl(ssock->sfd, BIOCGDLT, &ssock->lktype) < 0)
                break;

            if (ioctl(ssock->sfd, BIOCIMMEDIATE, &var) < 0)
                break;

            if (ioctl(ssock->sfd, BIOCSHDRCMPLT, &var) < 0)
                break;

            // AUXILIARY
            if ((priv = (struct SpkBpf *) calloc(1, sizeof(struct SpkBpf))) == NULL) {
                close(ssock->sfd);
                return SPKERR_ENOMEM;
            }

            if (ioctl(ssock->sfd, BIOCGBLEN, &priv->buflen) < 0) {
                free(priv);
                break;
            }

            if ((priv->buf = malloc(priv->buflen)) == NULL) {
                free(priv);
                close(ssock->sfd);
                return SPKERR_ENOMEM;
            }
            priv->cursor = priv->buf;

            if ((priv->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                free(priv->buf);
                free(priv);
                break;
            }

            ssock->aux = priv;
            ssock->direction = SPKDIR_BOTH;
            ssock->tsprc = SPKSTAMP_MICRO;
            ssock->op.read = spksock_bpf_read;
            ssock->op.setdir = spksock_bpf_setdir;
            ssock->op.setnblk = spksock_bpf_setnblock;
            ssock->op.setprc = spksock_bpf_setprc;
            ssock->op.setpromisc = spksock_bpf_setpromisc;
            ssock->op.write = spksock_bpf_write;
            ssock->op.finalize = spksock_bpf_finalize;
            return SPKERR_SUCCESS;
        }
    }

    if (ssock->sfd >= 0)
        close(ssock->sfd);
    return SPKERR_ERROR;
}

static void spksock_bpf_finalize(struct SpkSock *ssock) {
    struct SpkBpf *priv = ssock->aux;

    close(priv->sock);
    free(priv->buf);
    free(ssock->aux);
    close(ssock->sfd);
}

static int __bpf_get_hwaddr(struct SpkSock *ssock) {
    struct ifaddrs *ifa;
    struct ifaddrs *curr;
    struct sockaddr_dl *sdl;
    int error = SPKERR_ERROR;

    if (getifaddrs(&ifa) < 0)
        return error;

    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (strcmp(curr->ifa_name, ssock->iface_name) == 0) {
            if (curr->ifa_addr != NULL && curr->ifa_addr->sa_family == AF_LINK) {
                sdl = (struct sockaddr_dl *) curr->ifa_addr;
                switch (sdl->sdl_alen) {
                    case 0:
                        if ((curr->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
                            memset(ssock->iaddr.mac, 0x00, ETHHWASIZE);
                            error = SPKERR_SUCCESS;
                            break;
                        }
                        error = SPKERR_ERROR;
                        break;
                    case ETHHWASIZE:
                        memcpy(ssock->iaddr.mac, LLADDR(sdl), ETHHWASIZE);
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
    return error;
}

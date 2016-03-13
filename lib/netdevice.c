#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#ifdef __linux__
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#include <net/if_dl.h>
#endif

#include "netdevice.h"
#include "ethernet.h"

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa) {
#if defined(__linux__)
    /* struct ethtool_perm_addr{
        __u32   cmd;
        __u32   size;
        __u8    data[0];}
    */

    struct ifreq req;
    struct ethtool_perm_addr *epa;

    if ((epa = (struct ethtool_perm_addr *) malloc(sizeof(struct ethtool_perm_addr) + ETHHWASIZE)) == NULL)
        return false;
    epa->cmd = ETHTOOL_GPERMADDR;
    epa->size = ETHHWASIZE;

    memset(hwa, 0x00, sizeof(struct sockaddr));
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_data = (caddr_t) epa;

    if ((ioctl(sd, SIOCETHTOOL, &req) < 0)) {
        free(epa);
        return false;
    }
    else
        memcpy(hwa->sa_data, epa->data, ETHHWASIZE);
    free(epa);
    return true;
#else
    fprintf(stderr,"Not implemented yet!\n");
    return false;
#endif
}

/* sd = socket(AF_INET,SOCK_DGRAM,0) */
bool get_flags(int sd, char *iface_name, short *flags) {
    /* Get the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    if (ioctl(sd, SIOCGIFFLAGS, &req) < 0)
        return false;
    *flags = req.ifr_flags;
    return true;
}

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    /* Get the hardware address of a device using ifr_hwaddr. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
#if defined(__linux__)
    if (ioctl(sd, SIOCGIFHWADDR, &req) < 0)
        return false;
    memcpy(hwaddr, &req.ifr_hwaddr, sizeof(struct sockaddr));
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
    struct ifaddrs *ifa = NULL, *curr = NULL;
    if (getifaddrs(&ifa) < 0)
        return false;
    for (curr = ifa; curr != NULL && strcmp(curr->ifa_name,iface_name) == 0; curr = curr->ifa_next)
    {
        if(curr->ifa_addr!=NULL && curr->ifa_addr->sa_family==AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *) curr->ifa_addr;
            memcpy(hwaddr->sa_data, (sdl->sdl_data) + (sdl->sdl_nlen), ETHHWASIZE);
            break;
        }
        else
        {
            freeifaddrs(ifa);
            return false;
        }
    }
    freeifaddrs(ifa);
#endif
    return true;
}

bool set_flags(int sd, char *iface_name, short flags) {
    /* Set the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
    req.ifr_flags = flags;
    return ioctl(sd, SIOCSIFFLAGS, &req) >= 0;
}

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr) {
    /*
     * Set the hardware address of a device using ifr_hwaddr.
     * The hardware address is specified in a struct sockaddr.
     * sa_family contains the ARPHRD_* device type, sa_data the L2
     * hardware address starting from byte 0.
     */
    //https://forums.freebsd.org/threads/27606/
    // SIOCSIFLLADDR
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_name, iface_name);
#if defined(__linux__)
    memcpy(&req.ifr_hwaddr.sa_data, hwaddr->sa_data, ETHHWASIZE);
    req.ifr_hwaddr.sa_family = (unsigned short) 0x01;
    return ioctl(sd, SIOCSIFHWADDR, &req) >= 0;
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
    memcpy(&req.ifr_addr.sa_data, hwaddr->sa_data, ETHHWASIZE);
    req.ifr_addr.sa_family = (unsigned short) 0x01;
    return ioctl(sd, SIOCSIFADDR, &req) >= 0;
#endif
}

#if defined(__linux__)

int llsocket(char *iface_name) {
    int sock;
    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_halen = ETH_ALEN;
    sll.sll_protocol = htons(ETH_P_ALL);
    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        return sock;
    if ((sll.sll_ifindex = if_nametoindex(iface_name)) == 0)
        return -1;
    if (bind(sock, (struct sockaddr *) &sll, sizeof(struct sockaddr_ll)) < 0)
        return -1;
    return sock;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#pragma message "llsocket not implemented yet!"
int llsocket(char *iface_name) {
   fprintf(stderr,"Not implemented yet!\n");
   return false;
}
#endif
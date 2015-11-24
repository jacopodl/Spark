#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "netdhelper.h"

char *get_strhwaddr(struct sockaddr hwa)
{
    char *mac = (char *) malloc(MACSTRSIZ);
    if (mac == NULL)
        return NULL;
    sprintf(mac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
            (unsigned char) hwa.sa_data[0], (unsigned char) hwa.sa_data[1],
            (unsigned char) hwa.sa_data[2], (unsigned char) hwa.sa_data[3],
            (unsigned char) hwa.sa_data[4], (unsigned char) hwa.sa_data[5]);
    return mac;
}

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa)
{
    /* struct ethtool_perm_addr{
        __u32   cmd;
        __u32   size;
        __u8    data[0];}
    */

    struct ifreq req;
    struct ethtool_perm_addr *epa;

    if ((epa = (struct ethtool_perm_addr *) malloc(sizeof(struct ethtool_perm_addr) + IFHWADDRLEN)) == NULL)
        return false;
    epa->cmd = ETHTOOL_GPERMADDR;
    epa->size = IFHWADDRLEN;

    memset(hwa, 0x00, sizeof(struct sockaddr));
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_ifrn.ifrn_name, iface_name);
    req.ifr_data = (caddr_t) epa;

    if ((ioctl(sd, SIOCETHTOOL, &req) < 0)) {
        free(epa);
        return false;
    }
    else
        memcpy(hwa->sa_data, epa->data, IFHWADDRLEN);
    free(epa);
    return true;
}

/* sd = socket(AF_INET,SOCK_DGRAM,0) */
bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr)
{
    /* Get the hardware address of a device using ifr_hwaddr. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_ifrn.ifrn_name, iface_name);
    if (ioctl(sd, SIOCGIFHWADDR, &req) < 0)
        return false;
    memcpy(hwaddr, &req.ifr_ifru.ifru_hwaddr, sizeof(struct sockaddr));
    return true;
}

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr)
{
    /*
     * Set the hardware address of a device using ifr_hwaddr.
     * The hardware address is specified in a struct sockaddr.
     * sa_family contains the ARPHRD_* device type, sa_data the L2
     * hardware address starting from byte 0.
     */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_ifrn.ifrn_name, iface_name);
    memcpy(&req.ifr_ifru.ifru_hwaddr.sa_data, hwaddr->sa_data, IFHWADDRLEN);
    req.ifr_ifru.ifru_hwaddr.sa_family = (unsigned short) 0x01;
    return ioctl(sd, SIOCSIFHWADDR, &req) >= 0;
}

bool get_flags(int sd, char *iface_name, short *flags)
{
    /* Get the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_ifrn.ifrn_name, iface_name);
    if (ioctl(sd, SIOCGIFFLAGS, &req) < 0)
        return false;
    *flags = req.ifr_ifru.ifru_flags;
    return true;
}

bool set_flags(int sd, char *iface_name, short flags)
{
    /* Set the active flag word of the device. */
    struct ifreq req;
    memset(&req, 0x00, sizeof(struct ifreq));
    strcpy(req.ifr_ifrn.ifrn_name, iface_name);
    req.ifr_ifru.ifru_flags = flags;
    return ioctl(sd, SIOCSIFFLAGS, &req) >= 0;
}




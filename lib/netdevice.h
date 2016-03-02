#ifndef NETDEVICE
#define NETDEVICE

#include <stdbool.h>
#include <net/if.h>
#include <linux/if_packet.h>

bool build_sockaddr_ll(struct sockaddr_ll *iface, char *if_name,struct sockaddr *hwaddr);

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

#endif
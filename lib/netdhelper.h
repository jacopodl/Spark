#ifndef NETDHELPER
#define NETDHELPER

#include <stdbool.h>
#include <net/if.h>

#define MACSTRSIZ 19

void rndhwaddr(struct sockaddr *mac);

char *get_strhwaddr(struct sockaddr hwa);

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool get_flags(int sd, char *iface_name, short *flag);

bool set_flags(int sd, char *iface_name, short flags);

#endif
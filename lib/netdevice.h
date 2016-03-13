#ifndef NETDEVICE
#define NETDEVICE

#include <stdbool.h>


bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

int llsocket(char *iface_name);

#endif
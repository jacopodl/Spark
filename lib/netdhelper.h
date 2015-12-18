#ifndef NETDHELPER
#define NETDHELPER

#include <stdbool.h>
#include <net/if.h>

#define MACSTRSIZ 18

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr);

char *get_strhwaddr(struct sockaddr *hwa);

void rndhwaddr(struct sockaddr *mac);

#endif
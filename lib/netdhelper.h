#ifndef NETDHELPER
#define NETDHELPER

#include <stdbool.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define MACSTRSIZ   18
#define ETHHDRSIZ   14
#define ETHMAXPAYL  1500

struct eth_header{
    unsigned char dhwaddr[IFHWADDRLEN];
    unsigned char shwaddr[IFHWADDRLEN];
    unsigned int  eth_type:16;
};

bool build_sockaddr_ll(struct sockaddr_ll *iface, char *if_name,struct sockaddr *hwaddr);

bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr);

char *get_strhwaddr(struct sockaddr *hwa);

void rndhwaddr(struct sockaddr *mac);

#endif
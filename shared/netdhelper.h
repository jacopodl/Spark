#ifndef NETDHELPER
#define NETDHELPER

#include <net/if.h>

#define MACARRSIZ 6
#define MACSTRSIZ 19

int get_ifreq(struct ifreq *req);
int set_ifreq(struct ifreq *req);
char *get_hwaddr(struct ifreq *req);

#endif
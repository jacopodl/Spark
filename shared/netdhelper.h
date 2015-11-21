#ifndef NETDHELPER
#define NETDHELPER

#include <net/if.h>

#define MACSTRSIZ 19

int get_ifreq(int sd, struct ifreq *req);
int set_ifreq(int sd, struct ifreq *req);
char *get_strhwaddr(struct sockaddr hwa);
int get_burnedin_mac (int sd, struct ifreq *req, struct sockaddr *hwa);
#endif
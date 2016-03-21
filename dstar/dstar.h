#ifndef DSTAR
#define DSTAR

#include <net/if.h>
#include "../lib/netdevice.h"
#include "../lib/ethernet.h"
#include "../lib/dhcp.h"
#include "../lib/ipv4.h"
#include "../lib/udp.h"

#define APPNAME "dstar"
#define VERSION "1.00"

#define PKTLEN ETHHDRSIZE+IPV4HDRSIZE+UDPHDRSIZE+DHCPPKTLEN
#define IPPAYSIZE UDPHDRSIZE + DHCPPKTLEN

struct options {
    bool smac;
    bool sid;
    bool snum;
    bool sifn;
    unsigned int num;
    unsigned int xid;
    char iface_name[IFNAMSIZ];
    struct sockaddr hwaddr;
};

struct th_opt {
    bool st;
    int time;
    int ret;
    unsigned char *buff;
};

int dstar(struct options *opt);

void catch_signal(int signo);

void *mk_dos(void *time);

void usage();

#endif

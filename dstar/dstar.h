#ifndef DSTAR
#define DSTAR

#include <net/if.h>
#include "../lib/netdhelper.h"
#include "../lib/dhcphelper.h"
#include "../lib/ipv4helper.h"
#include "../lib/udphelper.h"

#define APPNAME "dstar"
#define VERSION "1.00"

#define PKTLEN ETHHDRSIZ+IPV4HDRSIZE+UDPHDRSIZE+DHCPPKTLEN

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
};

int dstar(struct options *opt);

void catch_signal(int signo);

void *mk_dos(void *time);

void usage();

#endif

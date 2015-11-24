#ifndef MSPOOF
#define MSPOOF

#define APPNAME "mspoof"
#define VERSION "1.00"

struct options {
    bool shl;
    bool set;
    bool rset;
    bool mac;
    bool rmac;
    int filter;
    char iface_name[IFNAMSIZ];
    struct sockaddr iface_hwaddr;
};

int make_spoof(struct options *opt);

int show_iface(int filter_flag);

void rndhwaddr(struct sockaddr *mac);

#endif
#ifndef NETDEVICE
#define NETDEVICE

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>

#define BPFPATHMAXLEN   11
#define BPFMAXDEV       99

#define NETD_UNSUCCESS      0
#define NETD_SUCCESS        1
#define NETD_UNSUPPORTED    -1

struct llOptions {
    char iface_name[IFNAMSIZ];
    char bsd_bind[BPFPATHMAXLEN];
    int sfd;
    unsigned long buffl;
};

struct ifList {
    char name[IFNAMSIZ];
    struct ifList *next;
};

int get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

int llclose(struct llOptions *llo, bool freemem);

int llsocket(struct llOptions *llo);

ssize_t llrecv(void *buff, struct llOptions *llo);

ssize_t llsend(const void *buff, unsigned long len, struct llOptions *llo);

struct ifList *get_iflist(unsigned int filter);

void iflist_cleanup(struct ifList *ifList);

void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl);

#endif

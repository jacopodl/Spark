#ifndef NETDEVICE
#define NETDEVICE

#include <stdbool.h>
#include <net/if.h>
#include <sys/socket.h>

// NETDEVICE OS
#define NETDEVLINUX     0
#define NETDEVBSD       1

#define BPFPATHMAXLEN   11
#define BPFMAXDEV       99

struct llOptions{
    char iface_name[IFNAMSIZ];
    char bsd_bind[BPFPATHMAXLEN];
    int sfd;
    unsigned long buffl;
};


bool get_burnedin_mac(int sd, char *iface_name, struct sockaddr *hwa);

bool get_flags(int sd, char *iface_name, short *flag);

bool get_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

bool set_flags(int sd, char *iface_name, short flags);

bool set_hwaddr(int sd, char *iface_name, struct sockaddr *hwaddr);

void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl);

int llsocket(struct llOptions *llo);

ssize_t llsend(const void *buff, unsigned long len,struct llOptions *llo);

ssize_t llrecv(void *buff, struct llOptions *llo);

int llclose(struct llOptions *llo, bool freemem);

#endif
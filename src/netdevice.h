/*
* <netdevice, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SPARK_NETDEVICE_H
#define SPARK_NETDEVICE_H

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include "datatype.h"

#define BPFPATHMAXLEN   11
#define BPFMAXDEV       99

#define NETD_UNSUCCESS      0
#define NETD_SUCCESS        1
#define NETD_NOTSUPPORTED    -1

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

int get_burnedin_mac(int sd, char *iface_name, struct netaddr_mac *hwa);

int get_flags(int sd, char *iface_name, short *flag);

int get_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

int llclose(struct llOptions *llo, bool freemem);

int llsocket(struct llOptions *llo, char *iface_name, unsigned int buffl);

int set_flags(int sd, char *iface_name, short flags);

int set_hwaddr(int sd, char *iface_name, struct netaddr_mac *hwaddr);

ssize_t llrecv(void *buff, struct llOptions *llo);

ssize_t llsend(const void *buff, unsigned long len, struct llOptions *llo);

struct ifList *get_iflist(unsigned int filter);

void iflist_cleanup(struct ifList *ifList);

static void init_lloptions(struct llOptions *llo, char *iface_name, unsigned int buffl);

#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "netdhelper.h"

int get_ifreq(int sd, struct ifreq *req)
{
	ioctl(sd,SIOCGIFHWADDR,req);
	return 0;
}

/* sd = socket(AF_INET,SOCK_DGRAM,0) */
int set_ifreq(int sd, struct ifreq *req)
{
	ioctl(sd,SIOCSIFHWADDR,req);
	return 0;
}

char *get_strhwaddr(struct sockaddr hwa)
{
	char *mac = (char*)malloc(MACSTRSIZ);
	if(mac==NULL)
		return NULL;
	sprintf(mac,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		(unsigned char)hwa.sa_data[0],(unsigned char)hwa.sa_data[1],
		(unsigned char)hwa.sa_data[2],(unsigned char)hwa.sa_data[3],
		(unsigned char)hwa.sa_data[4],(unsigned char)hwa.sa_data[5]);
	return mac;
}


int get_burnedin_mac (int sd, struct ifreq *req, struct sockaddr *hwa)
{
	 /* struct ethtool_perm_addr{
         __u32   cmd;
         __u32   size;
         __u8    data[0];} */
	int i;
	struct ifreq lreq;
	struct ethtool_perm_addr *epa;

	epa = (struct ethtool_perm_addr*) malloc(sizeof(struct ethtool_perm_addr) + IFHWADDRLEN);
	epa->cmd = ETHTOOL_GPERMADDR;
	epa->size = IFHWADDRLEN;

	memset(&lreq,0x00,sizeof(struct ifreq));
	strcpy(lreq.ifr_name,req->ifr_name);
	lreq.ifr_data = (caddr_t)epa;

	if ((i=ioctl(sd, SIOCETHTOOL, &lreq) < 0))
		return i;
	else
		for (i=0; i<IFHWADDRLEN; i++) 
			hwa->sa_data[i] = epa->data[i];
	free(epa);
	return 0;
}

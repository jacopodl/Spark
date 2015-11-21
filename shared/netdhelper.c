#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "netdhelper.h"

int get_ifreq(struct ifreq *req)
{
	int sd;
	if((sd = socket(AF_INET,SOCK_DGRAM,0))<0)
		return sd;
	ioctl(sd,SIOCGIFHWADDR,req);
	close(sd);
	return 0;
}

int set_ifreq(struct ifreq *req)
{
	int sd;
	if((sd = socket(AF_INET,SOCK_DGRAM,0))<0)
		return sd;
	ioctl(sd,SIOCSIFHWADDR,req);
	close(sd);
	return 0;
}

char *get_hwaddr(struct ifreq *req)
{
	char *mac = (char*)malloc(MACSTRSIZ);
	if(mac==NULL)
		return NULL;
	struct sockaddr hwa = req->ifr_hwaddr;
	sprintf(mac,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		(unsigned char)hwa.sa_data[0],(unsigned char)hwa.sa_data[1],
		(unsigned char)hwa.sa_data[2],(unsigned char)hwa.sa_data[3],
		(unsigned char)hwa.sa_data[4],(unsigned char)hwa.sa_data[5]);
	return mac;
}
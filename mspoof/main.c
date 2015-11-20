/*
-l --list list all iface
-s iface hwaddr
--sman iface manufacture
-r --restore iface
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
// http://man7.org/linux/man-pages/man7/netdevice.7.html
int main(int argc, char **argv)
{
	struct ifaddrs *ifa=NULL;
	int res = getifaddrs(&ifa);
	for(struct ifaddrs *curr=ifa;curr!=NULL;curr=curr->ifa_next)
	{
		if(curr->ifa_addr->sa_family!=AF_PACKET)
			continue;
		if(curr->ifa_flags&IFF_UP&&!(curr->ifa_flags&IFF_LOOPBACK))
		{
			int s;
    		struct ifreq buffer;
    		memset(&buffer,0x00,sizeof(buffer));
			strcpy(buffer.ifr_name, curr->ifa_name);
			get_set_ifreq(&buffer);
			printf("NIC: %s Mac: ", curr->ifa_name);
			for(int i=0;i<6;i++)
				printf("%.2X:",(unsigned char)buffer.ifr_hwaddr.sa_data[i]);
			printf("\n");
		}

	}
	freeifaddrs(ifa);
}

int get_set_ifreq(struct ifreq *req)
{
	int sd;
	if((sd = socket(AF_INET,SOCK_DGRAM,0))<0)
		return sd;
	ioctl(sd,SIOCGIFHWADDR,req);
	close(sd);
	return 0;
}
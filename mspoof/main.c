/*
-l --list list all iface
-u show up interface!
-s iface hwaddr
--sman iface manufacture
-r --random iface
*/
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include "../shared/netdhelper.h"
#include "../shared/argsx.h"
// http://man7.org/linux/man-pages/man7/netdevice.7.html

struct options
{
	bool shl;
	bool set;
	bool mac;
	int filter;
	char iface_name[IFNAMSIZ];
	unsigned int iface_hwaddr[MACARRSIZ];
};

void set_hwaddr(struct options *opt);

void usage()
{

}

void show_iface(int filter_flag);

int main(int argc, char **argv)
{
	if(argc<2)
	{
		usage();
		return -1;
	}

	struct options opt = {false,false,false,IFF_RUNNING,"\0",0};

	int ret;
	ax_lopt lopt[]={{(char*)"list",ARGSX_NOARG,'l'},
					{(char*)"up",ARGSX_NOARG,'u'},
					{(char*)"version",ARGSX_NOARG,'v'}};
	while((ret=argsx(argc,argv,(char*)"lus!r\0",lopt,sizeof(lopt),'-'))!=-1)
	{
		switch(ret)
		{
			case 'l':
				opt.shl = true;
				break;
			case 'u':
				opt.filter=IFF_UP;
				break;
			case 's':
				if(strlen(ax_arg)>=IFNAMSIZ)
				{
					fprintf(stderr,"%s name too long!\n",ax_arg);
					return -1;
				}
				strcpy(opt.iface_name,ax_arg);
				opt.set=true;
				break;
			case 'r':
				break;
			case ARGSX_BAD_OPT:
				return 0;
			case ARGSX_FEW_ARGS:
				return 0;
			case ARGSX_NONOPT:
				if(!opt.mac)
				{
					if (sscanf(ax_arg,"%x:%x:%x:%x:%x:%x", opt.iface_hwaddr,opt.iface_hwaddr+1,opt.iface_hwaddr+2,
						opt.iface_hwaddr+3,opt.iface_hwaddr+4,opt.iface_hwaddr+5) != 6)
					{
						fprintf(stderr,"Malformed mac addr!\n");
						return -1;
					}
				}
				break;
		}
	}
	if(opt.shl)
	{
		show_iface(opt.filter);
		return 0;
	}
	set_hwaddr(&opt);
	return 0;
}

void set_hwaddr(struct options *opt)
{

}

void show_iface(int filter_flag)
{
	struct ifaddrs *ifa=NULL;
	int res = getifaddrs(&ifa);
	printf("NIC:\t\tMAC:\n");
	for(struct ifaddrs *curr=ifa;curr!=NULL;curr=curr->ifa_next)
	{
		if(curr->ifa_addr->sa_family!=AF_PACKET)
			continue;
		if(curr->ifa_flags&filter_flag && !(curr->ifa_flags&IFF_LOOPBACK))
		{
    		struct ifreq iface_data;
    		memset(&iface_data,0x00,sizeof(iface_data));
			strcpy(iface_data.ifr_name, curr->ifa_name);
			get_ifreq(&iface_data);
			char *mac = get_hwaddr(&iface_data);
			printf("%s\t\t%s\n", curr->ifa_name, mac);
			free(mac);
		}
	}
	freeifaddrs(ifa);
}

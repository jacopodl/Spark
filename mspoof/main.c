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
#include <time.h>
#include "mspoof.h"
#include "../shared/netdhelper.h"
#include "../shared/argsx.h"
// http://man7.org/linux/man-pages/man7/netdevice.7.html

struct options
{
	bool shl;
	bool set;
	bool mac;
	bool rmac;
	int filter;
	char iface_name[IFNAMSIZ];
	struct sockaddr iface_hwaddr;
};

void set_hwaddr(struct options *opt);

void usage()
{
	printf("\n%s V: %s\n",APPNAME,VERSION);
	printf("Use: %s [OPTION]...\n"
		"Spoof MAC address.\n"
		"\t-h\t\tPrint this help\n"
		"\t-v, --version\tPrint version and exit\n"
		"\t-l, --list\tPrint all network interface with name and MAC\n"
		"\t-u\t\tCombined with -l shows the inactive interfaces\n"
		"\t-s\t\tSet the interface name to be spoofed\n"
		"\t-r, --random\tCombined with -s, build and set random MAC\n",APPNAME);
}


void show_iface(int filter_flag);

int main(int argc, char **argv)
{
	if(argc<2)
	{
		usage();
		return -1;
	}

	struct options opt = {false,false,false,false,IFF_RUNNING,"\0",0};

	int ret;
	ax_lopt lopt[]={{(char*)"help",ARGSX_NOARG,'h'},
					{(char*)"version",ARGSX_NOARG,'v'},
					{(char*)"list",ARGSX_NOARG,'l'},
					{(char*)"random",ARGSX_NOARG,'r'}};
	while((ret=argsx(argc,argv,(char*)"hvlus!r\0",lopt,sizeof(lopt),'-'))!=-1)
	{
		switch(ret)
		{
			case 'h':
				usage();
				return 0;
			break;
			case 'v':
				printf("%s V: %s\n", APPNAME,VERSION);
				return 0;
			break;
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
					opt.rmac=true;
				break;
			case ARGSX_BAD_OPT:
				return 0;
			case ARGSX_FEW_ARGS:
				return 0;
			case ARGSX_NONOPT:
				if(!opt.mac)
				{
					unsigned int hwaddr[IFHWADDRLEN];
					if (sscanf(ax_arg,"%x:%x:%x:%x:%x:%x", hwaddr,hwaddr+1,hwaddr+2,
						hwaddr+3,hwaddr+4,hwaddr+5) != 6)
					{
						fprintf(stderr,"Malformed mac addr!\n");
						return -1;
					}
					for(int i=0;i<IFHWADDRLEN;i++)
						opt.iface_hwaddr.sa_data[i]=(char)hwaddr[i];
				}
				break;
		}
	}
	if(opt.shl)
	{
		show_iface(opt.filter);
		return 0;
	}
	if(!opt.mac&&!opt.rmac)
	{
		fprintf(stderr,"-s required: [-r||mac_addr].\n");
		return -1;
	}
	set_hwaddr(&opt);
	return 0;
}

void set_hwaddr(struct options *opt)
{
	/* The LSB of the MSB can not be set, 
	 * because those are multicast mac addr! 
	srand(time(NULL));
	opt.iface_hwaddr[0]=(rand()%0xFF)&0xFE;
	for(int i=1;i<IFHWADDRLEN;i++)
		opt.iface_hwaddr[i]=rand()%0xFF; */
}

void show_iface(int filter_flag)
{
	struct ifaddrs *ifa=NULL;
	int sd, res;
	res = getifaddrs(&ifa);
	if((sd = socket(AF_INET,SOCK_DGRAM,0))<0)
		return;
	printf("NIC:\t\tMAC:\n");
	for(struct ifaddrs *curr=ifa;curr!=NULL;curr=curr->ifa_next)
	{
		if(curr->ifa_addr->sa_family!=AF_PACKET)
			continue;
		if(curr->ifa_flags&filter_flag && !(curr->ifa_flags&IFF_LOOPBACK))
		{
    		struct ifreq iface_data;
    		struct sockaddr burnin;

    		memset(&iface_data,0x00,sizeof(struct ifreq));
    		memset(&burnin,0x00,sizeof(struct sockaddr));
			strcpy(iface_data.ifr_name, curr->ifa_name);

			get_ifreq(sd,&iface_data);
			get_burnedin_mac(sd,&iface_data,&burnin);
			char *mac = get_strhwaddr(iface_data.ifr_hwaddr);
			char *bmac = get_strhwaddr(burnin);
			printf("%s\t\t%s - burnin: %s\n", curr->ifa_name, mac, bmac);
			free(mac);
			free(bmac);
		}
	}
	close(sd);
	freeifaddrs(ifa);
}

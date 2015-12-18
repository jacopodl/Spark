#include <stdlib.h>
#include <stdio.h>
#include "ipv4helper.h"
#include "netdhelper.h"

int main(int argc, char **argv)
{
	struct in_addr lol;
	parse_ipv4addr("192.168.1.254",&lol);
	for(int i=0;i<14;i++)
	{
		increment_ipv4addr(&lol);
		printf("reprint: %s\n",get_stripv4(&lol));
	}

	struct in_addr addr;
	struct in_addr netmask;
	struct in_addr ret;
	parse_ipv4addr("172.16.0.67",&addr);
	parse_ipv4addr("255.255.248.0",&netmask);
	printf("\nIp: %s\n",get_stripv4(&addr));
	printf("\nMask: %s\n",get_stripv4(&netmask));
	get_ipv4bcast_addr(&addr,&netmask,&ret);
	printf("\nBcastId: %s\n",get_stripv4(&ret));
	get_ipv4net_addr(&addr,&netmask,&ret);
	printf("\nNetId: %s\n",get_stripv4(&ret));
	get_ipv4wildcard_mask(&netmask,&ret);
	printf("\nWildcard: %s\n",get_stripv4(&ret));
}
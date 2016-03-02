#include <stdlib.h>
#include <stdio.h>
#include "ipv4.h"
#include "netdevice.h"

int main(int argc, char **argv)
{
	struct in_addr lol;
	struct in_addr ret;
	parse_ipv4addr("255.255.255.255",&lol);
	get_ipv4wildcard_mask(&lol,&ret); // errore!! 0.0.0.63
	printf("\nWildcard: %s\n",get_stripv4(&ret));
	for(int i=0;i<14;i++)
	{
		increment_ipv4addr(&lol);
		printf("reprint: %s\n",get_stripv4(&lol));
	}

	struct in_addr addr;
	struct in_addr netmask;
	parse_ipv4addr("172.16.0.67",&addr);
	parse_ipv4addr("255.255.248.0",&netmask);
	printf("\nIp: %s\n",get_stripv4(&addr));
	printf("\nMask: %s\n",get_stripv4(&netmask));
	get_ipv4bcast_addr(&addr,&netmask,&ret);
	printf("\nBcastId: %s\n",get_stripv4(&ret));
	get_ipv4net_addr(&addr,&netmask,&ret);
	printf("\nNetId: %s\n",get_stripv4(&ret));
	get_ipv4wildcard_mask(&lol,&ret);
	printf("\nWildcard: %s\n",get_stripv4(&ret));
}
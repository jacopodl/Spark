#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dnsq.h"
#include "../lib/dns.h"

int main(int argc, char **argv) {

    int sock;
    struct sockaddr_in to_server;

    unsigned long len = 0; // la lunghezza dovrebbe tornarla build_dns_query
    struct DnsHeader* dnsq = NULL;
    dnsq=build_dns_query(htons(0xeaca),OP_QUERY,TC_NOTTRUNCATED,RD_DESIRED);
    unsigned char *name = str_to_dns_query("www.unimi.it");
    append_dns_question(&dnsq,name,TY_A,CA_IN,&len);

    name = str_to_dns_query("www.unimi.it");
    append_dns_question(&dnsq,name,TY_MX,CA_IN,&len);


    if((sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)
        return -1;
    to_server.sin_family=AF_INET;
    to_server.sin_port=htons(53);
    inet_aton("208.67.220.220",&to_server.sin_addr);
    if (sendto(sock, dnsq, sizeof(struct DnsHeader)+len, 0, &to_server, sizeof(struct sockaddr_in))==-1)
        return -1;
    //usage();
    return 0;
}

void usage() {
    printf("\n%s V: %s\n"
                   "Dns explorer.\n", APPNAME, VERSION);
    printf("Usage: %s [OPTIONS]\n", APPNAME);
}
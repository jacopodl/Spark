//
// Created by jdl on 15/01/16.
//

#ifndef DHCPHELPER
#define DHCPHELPER

/* Values for OP field */
#define BOOT_REQUEST    1
#define BOOT_REPLY      2

/* Values for HTYPE field */
#define HTYPE_ETHER     1
#define HTYPE_IEEE802   6
#define HTYPE_FDDI      8

/* Value for flags field */
#define FLAGS_BROADCAST 0x8000

/* Values for option field */
#define MAGIC_COOKIE (0x63825363) /* Magic cookie validating dhcp options field (and bootp vendorextensions field). */

#define DHCP_REQUESTED_ADDRESS      50
#define DHCP_MESSAGE_TYPE           53
#define DHCP_SERVER_IDENTIFIER      54
#define DHCP_PARAMETER_REQUEST_LIST 55
#define DHCP_CLIENT_IDENTIFIER      61

#define SUBNET_MASK         1
#define ROUTERS             3
#define DOMAIN_NAME_SERVERS 6
#define DOMAIN_NAME         15
#define NTP_SERVERS         42


/* DHCP message types */
#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8

#define CHADDR_LEN  (16)
#define SNAME_LEN   (64)
#define FILE_LEN    (128)
#define OPTIONS_LEN (308)

#define DHCPPKTLEN  548
struct dhcp_pkt {
    unsigned int op:8;
    unsigned int htype:8;
    unsigned int hlen:8;
    unsigned int hops:8;
    unsigned int xid;
    unsigned int secs:16;
    unsigned int flags:16;  /* unused */
    unsigned int ciaddr;
    unsigned int yiaddr;
    unsigned int siaddr;
    unsigned int giaddr;
    unsigned char chaddr[CHADDR_LEN];
    unsigned char sname[SNAME_LEN];
    unsigned char file[FILE_LEN];
    unsigned int option;    /* MAGIC COOKIE */
    unsigned char options[OPTIONS_LEN];
};

struct dhcp_container{
    unsigned int op_ptr;
    struct dhcp_pkt dhcpPkt;
};

unsigned int mk_xid();
void dhcp_initialize(struct dhcp_container *container);
void build_dhcp_discover(struct dhcp_container *container, struct sockaddr *chaddr, struct in_addr *ipvreq);
void build_dhcp_request(struct dhcp_container *container, struct in_addr *ipvreq);
unsigned char *dhcp_get_options(struct dhcp_pkt *dhcpPkt);
unsigned char *dhcp_get_option_value(unsigned char option, struct dhcp_pkt *dhcpPkt);

#endif

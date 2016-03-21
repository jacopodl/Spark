#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include "dhcp.h"
#include "ipv4.h"

unsigned int mk_xid()
{
    srand((unsigned int)time(NULL));
    return (unsigned int) rand();
}

void dhcp_initialize(struct dhcp_container *container)
{
    container->op_ptr = 0;
    memset(&(container->dhcpPkt), 0x00, sizeof(struct dhcp_pkt));
}

void dhcp_append_option(struct dhcp_container *container, unsigned char op, unsigned char len, unsigned char *payload)
{
    container->dhcpPkt.options[container->op_ptr++] = op;
    container->dhcpPkt.options[container->op_ptr++] = len;
    memcpy((container->dhcpPkt.options + container->op_ptr), payload, len);
    container->op_ptr += len;
    container->dhcpPkt.options[container->op_ptr] = 0xFF;
}

void build_dhcp_discover(struct dhcp_container *container, struct sockaddr *chaddr, struct in_addr *ipvreq)
{
    dhcp_initialize(container);
    struct dhcp_pkt *dhcpPkt = &(container->dhcpPkt);
    dhcpPkt->op = BOOT_REQUEST;
    dhcpPkt->htype = HTYPE_ETHER;
    dhcpPkt->hlen = IFHWADDRLEN;
    dhcpPkt->xid = mk_xid();
    dhcpPkt->flags = FLAGS_BROADCAST;
    memcpy(dhcpPkt->chaddr, chaddr->sa_data, IFHWADDRLEN);

    dhcpPkt->option = htonl(MAGIC_COOKIE);

    dhcpPkt->options[container->op_ptr++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[container->op_ptr++] = 0x01;
    dhcpPkt->options[container->op_ptr++] = DHCPDISCOVER;

    unsigned char buff_client_id[IFHWADDRLEN + 1];
    buff_client_id[0] = HTYPE_ETHER;
    memcpy(buff_client_id + 1, chaddr->sa_data, IFHWADDRLEN);
    dhcp_append_option(container, DHCP_CLIENT_IDENTIFIER, IFHWADDRLEN + 1, buff_client_id);

    dhcp_append_option(container, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &(ipvreq->s_addr));

    unsigned char buff_parameter_request[] = {SUBNET_MASK, ROUTERS, DOMAIN_NAME, DOMAIN_NAME_SERVERS};
    dhcp_append_option(container, DHCP_PARAMETER_REQUEST_LIST, 0x04, buff_parameter_request);
}

void build_dhcp_request(struct dhcp_container *container, struct in_addr *ipvreq)
{
    struct dhcp_pkt *dhcpPkt = &(container->dhcpPkt);
    unsigned int xid = dhcpPkt->xid;
    unsigned int siaddr = dhcpPkt->siaddr;
    struct sockaddr chaddr;
    memcpy(chaddr.sa_data, dhcpPkt->chaddr, IFHWADDRLEN);
    dhcp_initialize(container);

    dhcpPkt->op = BOOT_REQUEST;
    dhcpPkt->htype = HTYPE_ETHER;
    dhcpPkt->hlen = IFHWADDRLEN;
    dhcpPkt->xid = xid;
    dhcpPkt->flags = FLAGS_BROADCAST;
    dhcpPkt->siaddr = siaddr;
    memcpy(dhcpPkt->chaddr, chaddr.sa_data, IFHWADDRLEN);

    dhcpPkt->option = htonl(MAGIC_COOKIE);

    dhcpPkt->options[container->op_ptr++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[container->op_ptr++] = 0x01;
    dhcpPkt->options[container->op_ptr++] = DHCPREQUEST;

    dhcp_append_option(container, DHCP_SERVER_IDENTIFIER, IPV4ADDRLEN, (unsigned char *) &siaddr);
    dhcp_append_option(container, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &(ipvreq->s_addr));
}

void dhcp_init_options(struct dhcp_container *container)
{
    container->op_ptr = 3;
    memset((container->dhcpPkt.options + container->op_ptr), 0x00, OPTIONS_LEN - container->op_ptr);
    container->dhcpPkt.options[container->op_ptr] = 0xFF;
}

unsigned char *dhcp_get_options(struct dhcp_pkt *dhcpPkt, unsigned int *len)
{
    *len=0;
    unsigned char *buffopt = dhcpPkt->options;
    unsigned char *olist = NULL;
    for (unsigned int i = 0; i < OPTIONS_LEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        unsigned char *tmp = (unsigned char *) realloc(olist, ++(*len));
        if (tmp == NULL) {
            if(olist!=NULL)
                free(olist);
            return NULL;
        }
        olist = tmp;
        olist[(*len) - 1] = buffopt[i];
    }
    return olist;
}

unsigned char *dhcp_get_option_value(unsigned char option, struct dhcp_pkt *dhcpPkt)
{
    unsigned char *buffopt = dhcpPkt->options;
    unsigned char *data = NULL;
    for (unsigned int i = 0; i < OPTIONS_LEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        if(buffopt[i]==option)
        {
            unsigned char len = buffopt[i+1];
            if(len>0) {
                data = (unsigned char *) malloc(buffopt[i + 1]);
                if (data != NULL)
                    memcpy(data, (buffopt + i + 2), buffopt[i + 1]);
            }
            break;
        }
    }
    return data;
}

void dhcp_replace_option(unsigned char option, unsigned char *value, unsigned char offset, struct dhcp_pkt *dhcpPkt)
{
    unsigned char *buffopt = dhcpPkt->options;
    for (unsigned int i = 0; i < OPTIONS_LEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        if(buffopt[i]==option)
        {
            memcpy((buffopt+(i+2))+offset,value,buffopt[i+1]-offset);
            return;
        }
    }
}
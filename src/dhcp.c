/*
* <dhcp, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>

#include "datatype.h"
#include "ipv4.h"
#include "dhcp.h"

struct DhcpPacket *build_dhcp_discover(struct netaddr_mac *chaddr, struct netaddr_ip *ipreq, unsigned int *optoff) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_discover((unsigned char *) dhcpPkt, chaddr, ipreq, optoff);
}

struct DhcpPacket *build_dhcp_request(struct netaddr_mac *chaddr, struct netaddr_ip *ipreq, unsigned int xid,
                                      struct netaddr_ip *siaddr, unsigned int *optoff) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_request((unsigned char *) dhcpPkt, chaddr, ipreq, xid, siaddr, optoff);
}

struct DhcpPacket *injects_dhcp_discover(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                         unsigned int *optoff) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) buff;
    *optoff = 0;
    dhcpPkt->op = DHCP_OP_BOOT_REQUEST;
    dhcpPkt->htype = DHCP_HTYPE_ETHER;
    dhcpPkt->hlen = IFHWADDRLEN;
    dhcpPkt->xid = dhcp_mkxid();
    dhcpPkt->flags = DHCP_FLAGS_BROADCAST;
    memcpy(dhcpPkt->chaddr, chaddr->mac, IFHWADDRLEN);

    dhcpPkt->option = htonl(DHCP_MAGIC_COOKIE);
    dhcpPkt->options[(*optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(*optoff)++] = 0x01;
    dhcpPkt->options[(*optoff)++] = DHCP_DISCOVER;

    unsigned char buff_client_id[IFHWADDRLEN + 1];
    buff_client_id[0] = DHCP_HTYPE_ETHER;
    memcpy(buff_client_id + 1, chaddr->mac, IFHWADDRLEN);

    dhcp_append_option(dhcpPkt, optoff, DHCP_CLIENT_IDENTIFIER, IFHWADDRLEN + 1, buff_client_id);
    dhcp_append_option(dhcpPkt, optoff, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &(ipreq->ip));
    unsigned char buff_parameter_request[] = {DHCP_REQ_SUBMASK, DHCP_REQ_ROUTERS, DHCP_REQ_DOMAIN_NAME, DHCP_REQ_DNS};
    dhcp_append_option(dhcpPkt, optoff, DHCP_PARAMETER_REQUEST_LIST, 0x04, buff_parameter_request);
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_request(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                        unsigned int xid, struct netaddr_ip *siaddr, unsigned int *optoff) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) buff;
    *optoff = 0;
    dhcpPkt->op = DHCP_OP_BOOT_REQUEST;
    dhcpPkt->htype = DHCP_HTYPE_ETHER;
    dhcpPkt->hlen = IFHWADDRLEN;
    dhcpPkt->xid = xid;
    dhcpPkt->flags = DHCP_FLAGS_BROADCAST;
    dhcpPkt->siaddr = siaddr->ip;
    memcpy(dhcpPkt->chaddr, chaddr->mac, IFHWADDRLEN);

    dhcpPkt->option = htonl(DHCP_MAGIC_COOKIE);
    dhcpPkt->options[(*optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(*optoff)++] = 0x01;
    dhcpPkt->options[(*optoff)++] = DHCP_REQUEST;

    dhcp_append_option(dhcpPkt, optoff, DHCP_SERVER_IDENTIFIER, IPV4ADDRLEN, (unsigned char *) &siaddr->ip);
    dhcp_append_option(dhcpPkt, optoff, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &ipreq->ip);
    return dhcpPkt;
}

unsigned char *dhcp_get_options(struct DhcpPacket *dhcpPkt, unsigned int *len) {
    *len = 0;
    unsigned char *buffopt = dhcpPkt->options;
    unsigned char *olist = NULL;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        unsigned char *tmp = (unsigned char *) realloc(olist, ++(*len));
        if (tmp == NULL) {
            free(olist);
            return NULL;
        }
        olist = tmp;
        olist[(*len) - 1] = buffopt[i];
    }
    return olist;
}

unsigned char *dhcp_get_option_value(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned int *len) {
    unsigned char *buffopt = dhcpPkt->options;
    unsigned char *data = NULL;
    *len = 0;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        if (buffopt[i] == option) {
            *len = buffopt[i + 1];
            if (*len > 0) {
                data = (unsigned char *) malloc(buffopt[i + 1]);
                if (data != NULL)
                    memcpy(data, (buffopt + i + 2), buffopt[i + 1]);
            }
            break;
        }
    }
    return data;
}

unsigned int dhcp_mkxid() {
    srand((unsigned int) time(NULL));
    return (unsigned int) rand();
}

void dhcp_append_option(struct DhcpPacket *dhcpPkt, unsigned int *optoff, unsigned char op, unsigned char len,
                        unsigned char *payload) {
    dhcpPkt->options[(*optoff)++] = op;
    dhcpPkt->options[(*optoff)++] = len;
    memcpy((dhcpPkt->options + (*optoff)), payload, len);
    *optoff += len;
    dhcpPkt->options[(*optoff)] = 0xFF;
}

void dhcp_init_options(struct DhcpPacket *dhcpPkt, unsigned int *optoff) {
    *optoff = 3;
    memset((dhcpPkt->options + 3), 0x00, DHCP_OPTLEN - (*optoff));
    dhcpPkt->options[*optoff] = 0xFF;
}

void dhcp_replace_option(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned char *value, unsigned char offset) {
    unsigned char *buffopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        if (buffopt[i] == option) {
            memcpy((buffopt + (i + 2)) + offset, value, buffopt[i + 1] - offset);
            return;
        }
    }
}
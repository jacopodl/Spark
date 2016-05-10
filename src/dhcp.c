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

bool dhcp_append_option(struct DhcpPacket *dhcpPkt, unsigned char op, unsigned char len, unsigned char *payload) {
    int i = 0;
    for (i; i < DHCP_OPTLEN && dhcpPkt->options[i] != 0xFF; i++);
    if (i == DHCP_OPTLEN)
        return false;
    dhcpPkt->options[i++] = op;
    dhcpPkt->options[i++] = len;
    memcpy((dhcpPkt->options + i), payload, len);
    i += len;
    dhcpPkt->options[i] = 0xFF;
    return true;
}

inline bool dhcp_check_type(struct DhcpPacket *dhcpPkt, unsigned char type) {
    return dhcp_get_type(dhcpPkt) == type;
}

bool dhcp_replace_option(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned char *value, unsigned char offset) {
    unsigned char *buffopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2) {
        if (buffopt[i] == option) {
            memcpy((buffopt + (i + 2)) + offset, value, buffopt[i + 1] - offset);
            return true;
        }
    }
    return false;
}

unsigned int dhcp_get_option_uint(struct DhcpPacket *dhcpPkt, unsigned char option) {
    unsigned char *buffopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2)
        if (buffopt[i] == option)
            return *((unsigned int *) (buffopt + i + 2));
    return 0;
}

struct DhcpPacket *build_dhcp_discover(struct netaddr_mac *chaddr, struct netaddr_ip *ipreq) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_discover((unsigned char *) dhcpPkt, chaddr, ipreq);
}

struct DhcpPacket *build_dhcp_raw(unsigned char *buff, unsigned char op, unsigned char htype, unsigned char hlen,
                                  unsigned char hops, unsigned int xid,
                                  unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                  struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                  struct netaddr *chaddr, char *sname) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_raw((unsigned char *) dhcpPkt, op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr,
                            giaddr, chaddr, sname);
}

struct DhcpPacket *build_dhcp_release(struct netaddr_mac *chaddr, struct netaddr_ip *ciaddr,
                                      struct netaddr_ip *server) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_release((unsigned char *) dhcpPkt, chaddr, ciaddr, server);
}

struct DhcpPacket *build_dhcp_request(struct netaddr_mac *chaddr, struct netaddr_ip *ipreq, unsigned int xid,
                                      struct netaddr_ip *siaddr) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTLEN);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_request((unsigned char *) dhcpPkt, chaddr, ipreq, xid, siaddr);
}

struct DhcpPacket *injects_dhcp_discover(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq) {

    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buff, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, IFHWADDRLEN, 0,
                                                  dhcp_mkxid(), 0, DHCP_FLAGS_BROADCAST, NULL, NULL, NULL, NULL,
                                                  (struct netaddr *) chaddr, NULL);
    int optoff = 0;

    dhcpPkt->options[optoff++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[optoff++] = 0x01;
    dhcpPkt->options[optoff++] = DHCP_DISCOVER;
    dhcpPkt->options[optoff] = 0xFF;

    unsigned char buff_client_id[IFHWADDRLEN + 1];
    buff_client_id[0] = DHCP_HTYPE_ETHER;
    memcpy(buff_client_id + 1, chaddr->mac, IFHWADDRLEN);

    //dhcp_append_option(dhcpPkt, DHCP_CLIENT_IDENTIFIER, IFHWADDRLEN + 1, buff_client_id);
    if (ipreq != NULL)
        dhcp_append_option(dhcpPkt, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &(ipreq->ip));
    unsigned char buff_parameter_request[] = {DHCP_REQ_SUBMASK, DHCP_REQ_ROUTERS, DHCP_REQ_DOMAIN_NAME, DHCP_REQ_DNS};
    dhcp_append_option(dhcpPkt, DHCP_PARAMETER_REQUEST_LIST, 0x04, buff_parameter_request);
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_raw(unsigned char *buff, unsigned char op, unsigned char htype, unsigned char hlen,
                                    unsigned char hops, unsigned int xid,
                                    unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                    struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                    struct netaddr *chaddr, char *sname) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) buff;
    memset(dhcpPkt, 0x00, DHCPPKTLEN);
    dhcpPkt->op = op;
    dhcpPkt->htype = htype;
    dhcpPkt->hlen = hlen;
    dhcpPkt->hops = hops;
    dhcpPkt->xid = xid;
    dhcpPkt->secs = secs;
    dhcpPkt->flags = flags;
    if (ciaddr != NULL)
        dhcpPkt->ciaddr = ciaddr->ip;
    if (yiaddr != NULL)
        dhcpPkt->yiaddr = yiaddr->ip;
    if (siaddr != NULL)
        dhcpPkt->siaddr = siaddr->ip;
    if (giaddr != NULL)
        dhcpPkt->giaddr = giaddr->ip;
    if (chaddr != NULL)
        memcpy(dhcpPkt->chaddr, chaddr->na_data, hlen);
    if (sname != NULL)
        memcpy(dhcpPkt->sname, sname, DHCP_SNAMELEN);
    dhcpPkt->option = htonl(DHCP_MAGIC_COOKIE);
    dhcpPkt->options[0] = 0xFF;
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_release(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ciaddr,
                                        struct netaddr_ip *server) {
    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buff, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, IFHWADDRLEN, 0,
                                                  dhcp_mkxid(), 0,
                                                  0, ciaddr, NULL, NULL, NULL,
                                                  (struct netaddr *) chaddr, NULL);
    int optoff = 0;
    dhcpPkt->options[(optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(optoff)++] = 0x01;
    dhcpPkt->options[(optoff)++] = DHCP_RELEASE;
    dhcpPkt->options[(optoff)] = 0xFF;

    dhcp_append_option(dhcpPkt, DHCP_SERVER_IDENTIFIER, IPV4ADDRLEN, (unsigned char *) &server->ip);
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_request(unsigned char *buff, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                        unsigned int xid, struct netaddr_ip *siaddr) {
    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buff, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, IFHWADDRLEN, 0, xid, 0,
                                                  DHCP_FLAGS_BROADCAST, NULL, NULL, siaddr, NULL,
                                                  (struct netaddr *) chaddr, NULL);
    int optoff = 0;
    dhcpPkt->options[(optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(optoff)++] = 0x01;
    dhcpPkt->options[(optoff)++] = DHCP_REQUEST;
    dhcpPkt->options[(optoff)] = 0xFF;

    dhcp_append_option(dhcpPkt, DHCP_SERVER_IDENTIFIER, IPV4ADDRLEN, (unsigned char *) &siaddr->ip);
    dhcp_append_option(dhcpPkt, DHCP_REQUESTED_ADDRESS, IPV4ADDRLEN, (unsigned char *) &ipreq->ip);
    return dhcpPkt;
}

unsigned char dhcp_get_type(struct DhcpPacket *dhcp) {
    return dhcp_get_option_uchar(dhcp, DHCP_MESSAGE_TYPE);
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

unsigned char dhcp_get_option_uchar(struct DhcpPacket *dhcpPkt, unsigned char option) {
    unsigned char *buffopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && buffopt[i] != 0xFF; i += buffopt[i + 1] + 2)
        if (buffopt[i] == option)
            return buffopt[i + 2];
    return 0;
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

inline unsigned int dhcp_mkxid() {
    srand((unsigned int) clock());
    return (unsigned int) rand();
}

void dhcp_init_options(struct DhcpPacket *dhcpPkt) {
    unsigned int optoff = 3;
    memset((dhcpPkt->options + 3), 0x00, DHCP_OPTLEN - optoff);
    dhcpPkt->options[optoff] = 0xFF;
}
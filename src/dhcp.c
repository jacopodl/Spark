/*
 * Copyright (c) 2016 Jacopo De Luca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <datatype.h>
#include <ethernet.h>
#include <ipv4.h>
#include <dhcp.h>

bool dhcp_append_option(struct DhcpPacket *dhcpPkt, unsigned char op, unsigned char len, unsigned char *payload) {
    int i = 0;
    for (i; i < DHCP_OPTLEN && dhcpPkt->options[i] != 0xFF; i++);
    if (i == DHCP_OPTLEN || (DHCP_OPTLEN - i) < 2 + len)
        return false;
    dhcpPkt->options[i++] = op;
    dhcpPkt->options[i++] = len;
    memcpy((dhcpPkt->options + i), payload, len);
    i += len;
    dhcpPkt->options[i] = 0xFF;
    return true;
}

inline bool dhcp_type_equals(struct DhcpPacket *dhcpPkt, unsigned char type) {
    return dhcp_get_type(dhcpPkt) == type;
}

unsigned int dhcp_get_option_uint(struct DhcpPacket *dhcpPkt, unsigned char option) {
    unsigned char *bufopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && bufopt[i] != 0xFF; i += bufopt[i + 1] + 2)
        if (bufopt[i] == option)
            return *((unsigned int *) (bufopt + i + 2));
    return 0;
}

struct DhcpPacket *build_dhcp_raw(unsigned char op, unsigned char htype, unsigned char hlen,
                                  unsigned char hops, unsigned int xid,
                                  unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                  struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                  struct netaddr *chaddr, char *sname) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) malloc(DHCPPKTSIZE);
    if (dhcpPkt == NULL)
        return NULL;
    return injects_dhcp_raw((unsigned char *) dhcpPkt, op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr,
                            giaddr, chaddr, sname);
}

struct DhcpPacket *injects_dhcp_discover(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                         unsigned short flags) {

    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buf, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, ETHHWASIZE, 0,
                                                  dhcp_mkxid(), 0, flags, NULL, NULL, NULL, NULL,
                                                  (struct netaddr *) chaddr, NULL);
    int optoff = 0;

    dhcpPkt->options[optoff++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[optoff++] = 0x01;
    dhcpPkt->options[optoff++] = DHCP_DISCOVER;
    dhcpPkt->options[optoff] = 0xFF;

    unsigned char buf_client_id[ETHHWASIZE + 1];
    buf_client_id[0] = DHCP_HTYPE_ETHER;
    memcpy(buf_client_id + 1, chaddr->mac, ETHHWASIZE);

    if (ipreq != NULL)
        dhcp_append_option(dhcpPkt, DHCP_REQUESTED_ADDRESS, IPV4ADDRSIZE, (unsigned char *) &(ipreq->ip));
    unsigned char buf_parameter_request[] = {DHCP_REQ_SUBMASK, DHCP_REQ_ROUTERS, DHCP_REQ_DOMAIN_NAME, DHCP_REQ_DNS};
    dhcp_append_option(dhcpPkt, DHCP_PARAMETER_REQUEST_LIST, 0x04, buf_parameter_request);
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_raw(unsigned char *buf, unsigned char op, unsigned char htype, unsigned char hlen,
                                    unsigned char hops, unsigned int xid,
                                    unsigned short secs, unsigned short flags, struct netaddr_ip *ciaddr,
                                    struct netaddr_ip *yiaddr, struct netaddr_ip *siaddr, struct netaddr_ip *giaddr,
                                    struct netaddr *chaddr, char *sname) {
    struct DhcpPacket *dhcpPkt = (struct DhcpPacket *) buf;
    memset(dhcpPkt, 0x00, DHCPPKTSIZE);
    dhcpPkt->op = op;
    dhcpPkt->htype = htype;
    dhcpPkt->hlen = hlen;
    dhcpPkt->hops = hops;
    dhcpPkt->xid = xid;
    dhcpPkt->secs = secs;
    dhcpPkt->flags = htons(flags);
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

struct DhcpPacket *injects_dhcp_release(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ciaddr,
                                        struct netaddr_ip *server, unsigned short flags) {
    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buf, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, ETHHWASIZE, 0,
                                                  dhcp_mkxid(), 0, flags, ciaddr, NULL, NULL, NULL,
                                                  (struct netaddr *) chaddr, NULL);
    int optoff = 0;
    dhcpPkt->options[(optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(optoff)++] = 0x01;
    dhcpPkt->options[(optoff)++] = DHCP_RELEASE;
    dhcpPkt->options[(optoff)] = 0xFF;

    dhcp_append_option(dhcpPkt, DHCP_SERVER_IDENTIFIER, IPV4ADDRSIZE, (unsigned char *) &server->ip);
    return dhcpPkt;
}

struct DhcpPacket *injects_dhcp_request(unsigned char *buf, struct netaddr_mac *chaddr, struct netaddr_ip *ipreq,
                                        unsigned int xid, struct netaddr_ip *siaddr,
                                        unsigned short flags) {
    struct DhcpPacket *dhcpPkt = injects_dhcp_raw(buf, DHCP_OP_BOOT_REQUEST, DHCP_HTYPE_ETHER, ETHHWASIZE, 0, xid, 0,
                                                  flags, NULL, NULL, siaddr, NULL, (struct netaddr *) chaddr, NULL);
    int optoff = 0;
    dhcpPkt->options[(optoff)++] = DHCP_MESSAGE_TYPE;
    dhcpPkt->options[(optoff)++] = 0x01;
    dhcpPkt->options[(optoff)++] = DHCP_REQUEST;
    dhcpPkt->options[(optoff)] = 0xFF;

    dhcp_append_option(dhcpPkt, DHCP_SERVER_IDENTIFIER, IPV4ADDRSIZE, (unsigned char *) &siaddr->ip);
    dhcp_append_option(dhcpPkt, DHCP_REQUESTED_ADDRESS, IPV4ADDRSIZE, (unsigned char *) &ipreq->ip);
    return dhcpPkt;
}

unsigned char dhcp_get_type(struct DhcpPacket *dhcp) {
    return dhcp_get_option_uchar(dhcp, DHCP_MESSAGE_TYPE);
}

unsigned char *dhcp_get_options(struct DhcpPacket *dhcpPkt, unsigned int *len) {
    *len = 0;
    unsigned char *bufopt = dhcpPkt->options;
    unsigned char *olist = NULL;
    for (unsigned int i = 0; i < DHCP_OPTLEN && bufopt[i] != 0xFF; i += bufopt[i + 1] + 2) {
        unsigned char *tmp = (unsigned char *) realloc(olist, ++(*len));
        if (tmp == NULL) {
            free(olist);
            return NULL;
        }
        olist = tmp;
        olist[(*len) - 1] = bufopt[i];
    }
    return olist;
}

unsigned char dhcp_get_option_uchar(struct DhcpPacket *dhcpPkt, unsigned char option) {
    unsigned char *bufopt = dhcpPkt->options;
    for (unsigned int i = 0; i < DHCP_OPTLEN && bufopt[i] != 0xFF; i += bufopt[i + 1] + 2)
        if (bufopt[i] == option)
            return bufopt[i + 2];
    return 0;
}

unsigned char *dhcp_get_option_value(struct DhcpPacket *dhcpPkt, unsigned char option, unsigned int *len) {
    unsigned char *bufopt = dhcpPkt->options;
    unsigned char *data = NULL;
    *len = 0;
    for (unsigned int i = 0; i < DHCP_OPTLEN && bufopt[i] != 0xFF; i += bufopt[i + 1] + 2) {
        if (bufopt[i] == option) {
            *len = bufopt[i + 1];
            if (*len > 0) {
                data = (unsigned char *) malloc(bufopt[i + 1]);
                if (data != NULL)
                    memcpy(data, (bufopt + i + 2), bufopt[i + 1]);
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
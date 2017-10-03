/*
 * Copyright (c) 2016 - 2017 Jacopo De Luca
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

#include <string.h>
#include <stdlib.h>

#include <datatype.h>
#include <arp.h>

struct ArpPacket *arp_build_packet(unsigned short hw_type, unsigned short proto, unsigned char hwalen,
                                   unsigned char pralen, unsigned short opcode, struct netaddr_generic *shwaddr,
                                   struct netaddr_generic *spraddr, struct netaddr_generic *dhwaddr,
                                   struct netaddr_generic *dpraddr) {
    unsigned int size = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    struct ArpPacket *arp = (struct ArpPacket *) malloc(size);

    if (arp == NULL)
        return NULL;

    arp_inject_packet((unsigned char *) arp,
                      hw_type,
                      proto,
                      hwalen,
                      pralen,
                      opcode,
                      shwaddr,
                      spraddr,
                      dhwaddr,
                      dpraddr);
    return arp;
}

struct ArpPacket *arp_inject_packet(unsigned char *buf, unsigned short hw_type, unsigned short proto,
                                    unsigned char hwalen, unsigned char pralen, unsigned short opcode,
                                    struct netaddr_generic *shwaddr, struct netaddr_generic *spraddr,
                                    struct netaddr_generic *dhwaddr, struct netaddr_generic *dpraddr) {
    struct ArpPacket *arp = (struct ArpPacket *) buf;
    unsigned char *data = (unsigned char *) arp->data;
    unsigned int tlen = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    memset(arp, 0x00, tlen);
    arp->hw_type = htons(hw_type);
    arp->proto = htons(proto);
    arp->hwalen = hwalen;
    arp->pralen = pralen;
    arp->opcode = htons(opcode);
    if (shwaddr != NULL)
        memcpy(data, shwaddr->na_data, hwalen);
    data += hwalen;
    if (spraddr != NULL)
        memcpy(data, spraddr->na_data, pralen);
    data += pralen;
    if (dhwaddr != NULL)
        memcpy(data, dhwaddr->na_data, hwalen);
    data += hwalen;
    if (dpraddr != NULL)
        memcpy(data, dpraddr->na_data, pralen);
    return arp;
}

struct ArpPacket *arp_inject_reply(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                   struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return arp_inject_packet(buf,
                             ARPHWT_ETH,
                             ETHTYPE_IP,
                             ETHHWASIZE,
                             IPADDRSIZE,
                             ARPOP_REPLY,
                             (struct netaddr_generic *) shwaddr,
                             (struct netaddr_generic *) spraddr,
                             (struct netaddr_generic *) dhwaddr,
                             (struct netaddr_generic *) dpraddr);
}

struct ArpPacket *arp_inject_request(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                     struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return arp_inject_packet(buf,
                             ARPHWT_ETH,
                             ETHTYPE_IP,
                             ETHHWASIZE,
                             IPADDRSIZE,
                             ARPOP_REQUEST,
                             (struct netaddr_generic *) shwaddr,
                             (struct netaddr_generic *) spraddr,
                             (struct netaddr_generic *) dhwaddr,
                             (struct netaddr_generic *) dpraddr);
}

struct netaddr_ip arp_getaddr_d(struct ArpPacket *ap) {
    netaddr_ip(ip);
    ip.ip = *((unsigned int *) (ap->data + ETHHWASIZE + IPADDRSIZE + ETHHWASIZE));
    return ip;
}

struct netaddr_ip arp_getaddr_s(struct ArpPacket *ap) {
    netaddr_ip(ip);
    ip.ip = *((unsigned int *) (ap->data + ETHHWASIZE));
    return ip;
}

struct netaddr_mac arp_gethwaddr_d(struct ArpPacket *ap) {
    netaddr_mac(mac);
    memcpy(mac.mac, (ap->data + ETHHWASIZE + IPADDRSIZE), ETHHWASIZE);
    return mac;
}

struct netaddr_mac arp_gethwaddr_s(struct ArpPacket *ap) {
    netaddr_mac(mac);
    memcpy(mac.mac, ap->data, ETHHWASIZE);
    return mac;
}
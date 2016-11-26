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

#include <string.h>
#include <stdlib.h>

#include <datatype.h>
#include <arp.h>

struct ArpPacket *build_arp_packet(unsigned char hwalen, unsigned char pralen, unsigned short opcode,
                                   struct netaddr *shwaddr, struct netaddr *spraddr, struct netaddr *dhwaddr,
                                   struct netaddr *dpraddr) {
    unsigned long size = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    struct ArpPacket *arp = (struct ArpPacket *) malloc(size);
    if (arp == NULL)
        return NULL;
    injects_arp_packet((unsigned char *) arp, hwalen, pralen, opcode, shwaddr, spraddr, dhwaddr, dpraddr);
    return arp;
}

struct ArpPacket *injects_arp_packet(unsigned char *buf, unsigned char hwalen, unsigned char pralen,
                                     unsigned short opcode, struct netaddr *shwaddr, struct netaddr *spraddr,
                                     struct netaddr *dhwaddr, struct netaddr *dpraddr) {
    struct ArpPacket *arp = (struct ArpPacket *) buf;
    unsigned char *data = (unsigned char *) arp->data;
    unsigned int tlen = (unsigned int) ARPHDRSIZE + ((hwalen + pralen) * 2);
    memset(arp, 0x00, tlen);
    arp->hw_type = htons(ARPHWT_ETH);
    arp->proto = htons(ETHTYPE_IP);
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

struct ArpPacket *injects_arp_reply(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                    struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return injects_arp_packet(buf, ETHHWASIZE, IPV4ADDRSIZE, ARPOP_REPLY, (struct netaddr *) shwaddr,
                              (struct netaddr *) spraddr, (struct netaddr *) dhwaddr, (struct netaddr *) dpraddr);
}

struct ArpPacket *injects_arp_request(unsigned char *buf, struct netaddr_mac *shwaddr, struct netaddr_ip *spraddr,
                                      struct netaddr_mac *dhwaddr, struct netaddr_ip *dpraddr) {
    return injects_arp_packet(buf, ETHHWASIZE, IPV4ADDRSIZE, ARPOP_REQUEST, (struct netaddr *) shwaddr,
                              (struct netaddr *) spraddr, (struct netaddr *) dhwaddr, (struct netaddr *) dpraddr);
}

struct netaddr_ip arp_getaddr_d(struct ArpPacket *ap) {
    struct netaddr_ip ip;
    ip.ip = *((unsigned int *) (ap->data + ap->hwalen + ap->pralen + ap->hwalen));
    return ip;
}

struct netaddr_ip arp_getaddr_s(struct ArpPacket *ap) {
    struct netaddr_ip ip;
    ip.ip = *((unsigned int *) (ap->data + ap->hwalen));
    return ip;
}

struct netaddr_mac arp_gethwaddr_d(struct ArpPacket *ap) {
    struct netaddr_mac mac;
    memcpy(mac.mac, (ap->data + ap->hwalen + ap->pralen), ap->hwalen);
    return mac;
}

struct netaddr_mac arp_gethwaddr_s(struct ArpPacket *ap) {
    struct netaddr_mac mac;
    memcpy(mac.mac, ap->data, ap->hwalen);
    return mac;
}
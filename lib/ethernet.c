//
// Created by jdl on 24/02/16.
//

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "ethernet.h"

bool parse_hwaddr(char *hwstr, struct sockaddr *ret_sockaddr, bool bcast) {
    if (strlen(hwstr) >= MACSTRSIZE)
        return false;
    unsigned int hwaddr[ETHHWASIZE];
    if (sscanf(hwstr, "%x:%x:%x:%x:%x:%x", hwaddr, hwaddr + 1, hwaddr + 2, hwaddr + 3, hwaddr + 4, hwaddr + 5) != 6)
        return false;
    if (!bcast && hwaddr[0] & ~0xFE)
        return false;
    if (ret_sockaddr != NULL)
        for (int i = 0; i < ETHHWASIZE; i++)
            ret_sockaddr->sa_data[i] = (char) hwaddr[i];
    return true;
}

char *get_strhwaddr(struct sockaddr *hwa, bool _static) {
    static char macs[MACSTRSIZE];
    char *mac = macs;
    if(!_static)
        if((mac = (char *) malloc(MACSTRSIZE))==NULL)
            return NULL;
    sprintf(mac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
            (unsigned char) hwa->sa_data[0], (unsigned char) hwa->sa_data[1],
            (unsigned char) hwa->sa_data[2], (unsigned char) hwa->sa_data[3],
            (unsigned char) hwa->sa_data[4], (unsigned char) hwa->sa_data[5]);
    return mac;
}

struct EthHeader *build_ethernet_packet(struct sockaddr *src, struct sockaddr *dst, unsigned short type,
                                         unsigned long paysize, unsigned char *payload) {
    unsigned long size = sizeof(struct EthHeader) + paysize;
    struct EthHeader *ret = (struct EthHeader *) malloc(size);
    if (ret == NULL)
        return NULL;
    memset(ret, 0x00, size);
    memcpy(ret->dhwaddr, dst->sa_data, ETHHWASIZE);
    memcpy(ret->shwaddr, src->sa_data, ETHHWASIZE);
    ret->eth_type = htons(type);
    if(payload!=NULL)
        memcpy(ret->data, payload, paysize);
    return ret;
}

void injects_ethernet_header(unsigned char *buff, struct sockaddr *src, struct sockaddr *dst, unsigned short type)
{
    struct EthHeader *ret = (struct EthHeader *) buff;
    memset(ret, 0x00, sizeof(struct EthHeader));
    memcpy(ret->dhwaddr, dst->sa_data, ETHHWASIZE);
    memcpy(ret->shwaddr, src->sa_data, ETHHWASIZE);
    ret->eth_type = htons(type);
}

inline void build_ethbroad_addr(struct sockaddr *addr)
{
    memset(addr->sa_data,0xFF,ETHHWASIZE);
}

void build_ethmulti_addr(struct sockaddr *hw, struct in_addr *ip)
{
    ip->s_addr &=  ~ 0xFF;
    char *ip_ptr = (char *) &ip->s_addr;
    memset(hw->sa_data,0x00,ETHHWASIZE);
    *((int *)hw->sa_data) = htonl(0x01005E00);
    memset(hw->sa_data+3,ip_ptr[1],1);
    memset(hw->sa_data+4,ip_ptr[2],1);
    memset(hw->sa_data+5,ip_ptr[3],1);
    //printf("mac: %s",get_strhwaddr(hw));
    return;
}

void rndhwaddr(struct sockaddr *mac) {
/* The lsb of the MSB can not be set,
 * because those are multicast mac addr!
 */
    memset(mac, 0x00, sizeof(struct sockaddr));
    FILE *urandom;
    urandom = fopen("/dev/urandom", "r");
    unsigned char byte;
    for (int i = 0; i < ETHHWASIZE; i++) {
        fread(&byte, 1, 1, urandom);
        switch (i) {
            case 0:
                mac->sa_data[i] = byte & ((char) 0xFE);
                break;
            default:
                mac->sa_data[i] = byte;
        }
    }
    fclose(urandom);
}
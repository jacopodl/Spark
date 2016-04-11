//
// Created by jdl on 24/02/16.
//

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "dns.h"


unsigned char *str_to_dns_query(char *str) {
    unsigned int pos = 0;
    unsigned long len = strlen(str);
    if(len > 255)
        return NULL;
    unsigned char *ret = (unsigned char *) malloc(len + 1);
    if (ret == NULL)
        return NULL;
    for (int i = 0; i <= len; i++) {
        if (str[i] == '.' || str[i] == '\0') {
            ret[pos] = (unsigned char) (i - pos);
            pos += (i - pos) + 1;
        }
        else
            ret[i + 1] = (unsigned char) str[i];
    }
    ret[len + 1] = '\0';
    return ret;
}

struct DnsHeader *build_dns_query(unsigned short id, unsigned char op, unsigned char tc, unsigned char rd)
{
    struct DnsHeader *dns = (struct DnsHeader*)malloc(sizeof(struct DnsHeader));
    if(dns==NULL)
        return NULL;
    memset(dns,0x00,sizeof(struct DnsHeader));
    dns->qr=QR_QUERY;
    dns->id=id;
    dns->op=op;
    dns->tc=tc;
    dns->rd=rd;
    return dns;
}

bool append_dns_question(struct DnsHeader **rbuff,unsigned char *query, unsigned short type, unsigned short class, unsigned long *len)
{
    type=htons(type);
    class = htons(class);
    unsigned long lenWithNull = strlen((char*)query)+1;
    struct DnsHeader *dns = (struct DnsHeader*)realloc(*rbuff,sizeof(struct DnsHeader)+(*len)+lenWithNull+4);
    if(dns==NULL)
        return false;
    memcpy(dns->data+(*len),query,lenWithNull);
    *len+=lenWithNull;
    memcpy(dns->data+((*len)),(char *)&type,2);
    memcpy(dns->data+((*len)+2),(char *)&class,2);
    dns->totalqs+=htons(1);
    (*rbuff)=dns;
    (*len)+=4;
    return true;
}

void injects_dns_query(unsigned char *buff, unsigned short id, unsigned char op, unsigned char tc, unsigned char rd)
{
    struct DnsHeader *dns = (struct DnsHeader*)buff;
    memset(dns,0x00,sizeof(struct DnsHeader));
    dns->qr=QR_QUERY;
    dns->id=id;
    dns->op=op;
    dns->tc=tc;
    dns->rd=rd;
}

/*
void injects_dns_question(unsigned char *buff,char *query, unsigned short type, unsigned short class, unsigned long len)
{
    struct DnsHeader *dns = (struct DnsHeader*)ret;
    memcpy(ret+(*len),query,lenWithNull);
    *len+=lenWithNull;
    memcpy(ret+((*len)),(char *)&type,2);
    memcpy(ret+((*len)+2),(char *)&class,2);
    dns->totalqs+=htons(1);
    (*rbuff)=ret;
    (*len)+=4;
    return true;


    unsigned long lenWithNull = strlen(query)+1;
    unsigned char *ret = realloc(*rbuff,(*len)+lenWithNull+4);
    if(ret == NULL)
        return false;
    struct DnsHeader *dns = (struct DnsHeader*)ret;
    memcpy(ret+(*len),query,lenWithNull);
    *len+=lenWithNull;
    memcpy(ret+((*len)),(char *)&type,2);
    memcpy(ret+((*len)+2),(char *)&class,2);
    dns->totalqs+=htons(1);
    (*rbuff)=ret;
    (*len)+=4;
    return true;
}
 */
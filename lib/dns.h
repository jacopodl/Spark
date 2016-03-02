#ifndef DNS
#define DNS

#include <stdbool.h>

#define DNSHDRSIZE          12

#define QR_QUERY    0
#define QR_RESPONSE 1

#define OP_QUERY    0
#define OP_IQUERY   1
#define OP_STATUS   2
#define OP_NOTIFY   4
#define OP_UPDATE   5

#define AA_NOTAUTHORITATIVE 0
#define AA_AUTHORITATIVE    1

#define TC_NOTTRUNCATED 0
#define TC_TRUNCATED    1

#define RD_NOTDESIRED   0
#define RD_DESIRED      1

#define RA_NOTAVAILABLE 0
#define RA_AVAILABLE    1

#define AD_UNACCEPTABLE 0
#define AD_ACCEPTABLE   1

#define RC_NOERROR          0
#define RC_FORMATERROR      1
#define RC_SERVERFAILURE    2
#define RC_NAMERROR         3
#define RC_NOTIMPLEMENTED   4
#define RC_REFUSED          5
#define RC_YXDOMAIN         6
#define RC_YXRRSET          7
#define RC_NXRRSET          8
#define RC_NOTAUTH          9
#define RC_NOTZONE          10
#define RC_BADVERS          16
#define RC_BADSIG           16
#define RC_BADKEY           17
#define RC_BADTIME          18
#define RC_BADMODE          19
#define RC_BADNAME          20
#define RC_BADALG           21
#define RC_BADTRUNC         22

// http://www.networksorcery.com/enp/protocol/dns.htm#Questions

struct DnsHeader {
    unsigned int id:16;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char rd:1;
    unsigned char tc:1;
    unsigned char aa:1;
    unsigned char op:4;
    unsigned char qr:1;
    unsigned char rcode:4;
    unsigned char cd:1;
    unsigned char ad:1;
    unsigned char z:1;
    unsigned char ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char qr:1;
    unsigned char op:4;
    unsigned char aa:1;
    unsigned char tc:1;
    unsigned char rd:1;
    unsigned char ra:1;
    unsigned char z:1;
    unsigned char ad:1;
    unsigned char cd:1;
    unsigned char rcode:4;
#endif

    unsigned int totalqs:16;
    unsigned int totalans:16;
    unsigned int totalauth:16;
    unsigned int totaladd:16;
    unsigned char data[0];
};

unsigned char *str_to_dns_query(char *str);

bool append_dns_question(struct DnsHeader **rbuff,unsigned char *query, unsigned short type, unsigned short class, unsigned long *len);

struct DnsHeader *build_dns_query(unsigned short id, unsigned char op, unsigned char tc, unsigned char rd);

#endif

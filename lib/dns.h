#ifndef DNS
#define DNS

#include <stdbool.h>

#define DNSHDRSIZE  12

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

#define TY_A                1
#define TY_NS               2
#define TY_CNAME            5
#define TY_SOA              6
#define TY_MB               7
#define TY_MG               8
#define TY_MR               9
#define TY_NULL             10
#define TY_WKS              11
#define TY_PTR              12
#define TY_HINFO            13
#define TY_MINFO            14
#define TY_MX               15
#define TY_TXT              16
#define TY_RP               17
#define TY_GPOS             27
#define TY_AAAA             28
#define TY_LOC              29
#define TY_EID              31
#define TY_KX               36
#define TY_CERT             37
#define TY_A6               38
#define TY_DNAME            39
#define TY_DS               43
#define TY_SSHFP            44
#define TY_IPSECKEY         45
#define TY_DHCID            49
#define TY_HIP              55
#define TY_NINFO            56
#define TY_CAA              257

#define CA_IN               1
#define CA_CH               3
#define CA_HS               4
#define CA_NONE             254
#define CA_ANY              255


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

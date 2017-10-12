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

/**
 * @file dns.h
 * @brief Provides useful functions for manage DNS packets.
 */

#ifndef SPARK_DNS_H
#define SPARK_DNS_H

#define DNSQR_QUERY     0
#define DNSQR_RESPONSE  1

#define DNSOP_QUERY     0
#define DNSOP_IQUERY    1
#define DNSOP_STATUS    2
#define DNSOP_NOTIFY    4
#define DNSOP_UPDATE    5

#define DNSAA_NOTAUTH   0
#define DNSAA_AUTH      1

#define DNSTC_NOTTRUNC  0
#define DNSTC_TRUNC     1

#define DNSRD_NOTRECURSION  0
#define DNSRD_RECURSION     1

#define DNSRA_NOTAVAILABLE  0
#define DNSRA_AVAILABLE     1

#define DNSRC_NOERROR           0
#define DNSRC_FORMATERR         1
#define DNSRC_SERVERFAIL        2
#define DNSRC_NAMEERROR         3
#define DNSRC_NOTIMPLEMENTED    4
#define DNSRC_REFUSED           5
#define DNSRC_NOTAUTH           9
#define DNSRC_NOTZONE           10

#define DNSTYPE_A       1
#define DNSTYPE_NS      2
#define DNSTYPE_MD      3
#define DNSTYPE_MF      4
#define DNSTYPE_CNAME   5
#define DNSTYPE_SOA     6
#define DNSTYPE_MB      7
#define DNSTYPE_MG      8
#define DNSTYPE_MR      9
#define DNSTYPE_NULL    10
#define DNSTYPE_WKS     11
#define DNSTYPE_PTR     12
#define DNSTYPE_HINFO   13
#define DNSTYPE_MINFO   14
#define DNSTYPE_MX      15
#define DNSTYPE_TXT     16
#define DNSTYPE_AAAA    28
#define DNSTYPE_LOC     29
#define DNSTYPE_NXT     30

#define DNSCLASS_IN     1
#define DNSCLASS_CH     3
#define DNSCLASS_HS     4
#define DNSCLASS_ANY    255

/// @brief This structure represents Dns header.
struct DnsHeader {
    unsigned short id;
    unsigned char qr:1;
    unsigned char opcode:4;
    unsigned char aa:1;
    unsigned char tc:1;
    unsigned char rd:1;
    unsigned char ra:1;
    unsigned char z:1;
    unsigned char ad:1;
    unsigned char cd:1;
    unsigned char rcode:4;
    unsigned short total_questions;
    unsigned short total_answers;
    unsigned short total_authority;
    unsigned short total_additional;
    unsigned char data[];
};

/// @brief This structure represents Dns query.
struct DnsQuery {
    /// @brief Query type, Eg: A, MX, AAAA...
    unsigned short type;
    /// @brief Class Eg: IN (Internet).
    unsigned short clazz;
};

/// @brief This structure represents Dns resource record.
struct DnsResourceRecord {
    /// @brief Answer type, Eg: A, MX, AAAA...
    unsigned short type;
    /// @brief Class Eg: IN (Internet).
    unsigned short clazz;
    /// @brief Time to live.
    unsigned int ttl;
    /// @brief Data length.
    unsigned short length;
};

/**
 * @brief Returns pointer to DNS answer section (if present).
 *
 * @param __IN__dns Pointer to DnsHeader.
 * @return On success returns pointer to DNS answer section, otherwise returns NULL.
 */
unsigned char *dns_answerptr(struct DnsHeader *dns);

/**
 * @brief Returns new string that contains url.
 *
 * @param __IN__buf Pointer to DNS section contains domain name in DNS format(Eg: 3www6google3com0).
 * @return On success returns new string that contains url, otherwise returns NULL.
 */
char *dns_dntostr(unsigned char *buf);

/**
 * @brief Returns pointer to DNS query section.
 *
 * @param __IN__dns Pointer to DNS section contains domain name.
 * @return Pointer to DNS query section.
 */
struct DnsQuery *dns_getquery(unsigned char *buf);

/**
 * @brief Returns pointer to DNS resource record.
 *
 * @param __IN__dns Pointer to DNS section contains domain name.
 * @return Pointer to DNS resource record.
 */
struct DnsResourceRecord *dns_getrr(unsigned char *buf);

/**
 * @brief Convert(to DNS format) and inject name into a pre-allocated buffer.
 *
 * @param __IN__buf Pointer to DNS section where will be inject domain name.
 * @param __IN__url Pointer to url string Eg: "www.google.com".
 * @return On success returns pointer that point at the end of injected string.
 */
unsigned char *dns_inject_dn(unsigned char *buf, const char *url);

/**
 * @brief Returns new buffer that contains DNS domain name(Eg: 3www6google3com0).
 *
 * @param __IN__url Pointer to url string Eg: "www.google.com".
 * @return On success returns new string that contains DNS domain name, otherwise returns NULL.
 */
unsigned char *dns_strtodn(const char *url, int *rlen);

#endif //SPARK_DNS_H

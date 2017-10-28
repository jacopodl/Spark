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

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <dns.h>

bool dns_qndn_equals(struct DnsHeader *dns, unsigned char *qname, const char *dname) {
    int dnlen;

    if (*qname == 0)
        return *dname == '.' && *(dname + 1) == '\0';

    if ((ntohs(*((unsigned short *) qname)) & 0xC000) == 0xC000)
        qname = (dns->data + (ntohs(*((unsigned short *) qname)) - 0xC000) - 0x0C);

    dnlen = *qname++;

    for (int cursor = 0;; cursor++) {
        if (dnlen-- == 0) {
            if ((ntohs(*((unsigned short *) (qname))) & 0xC000) == 0xC000)
                qname = (dns->data + (ntohs(*((unsigned short *) qname)) - 0xC000) - 0x0C);
            dnlen = *qname++;
            if (dnlen != 0 && dname[cursor] != '.')
                return false;
            if (dnlen == 0 && dname[cursor] == '\0')
                return true;
            continue;
        }
        if (*qname++ != dname[cursor] || dname[cursor] == '\0')
            return false;
    }
}

unsigned char *dns_jmpto_answers(struct DnsHeader *dns) {
    int questions = ntohs(dns->total_questions);
    unsigned char *aptr = dns->data;

    if (ntohs(dns->total_answers) == 0)
        return NULL;

    while (questions-- > 0) {
        aptr = (unsigned char *) dns_getquery(aptr);
        aptr += sizeof(struct DnsQuery);
    }
    return aptr;
}

unsigned char *dns_jmpto_queries(struct DnsHeader *dns) {
    if (ntohs(dns->total_questions) == 0)
        return NULL;
    return dns->data;
}

unsigned char *dns_inject_qn(unsigned char *buf, const char *dname) {
    int len = 0;
    int ins = 0;
    int i = 0;
    unsigned char count = 0;

    len = (int) strlen(dname);

    for (i = 0; i < len; i++) {
        if (dname[i] == '.') {
            buf[ins] = count;
            ins = i + 1;
            count = 0;
            continue;
        }
        buf[i + 1] = (unsigned char) dname[i];
        count++;
    }

    buf[ins] = count;
    buf[++i] = 0x00;
    return buf + i + 1;
}

unsigned char *dns_dntoqn(const char *dname, int *rlen) {
    unsigned char *str;

    if ((str = malloc(strlen(dname) + 2)) == NULL)
        return NULL;

    dns_inject_qn(str, dname);
    *rlen = (int) (strlen(dname) + 2);

    return str;
}

struct DnsQuery *dns_getquery(unsigned char *buf) {
    unsigned char jmp;

    jmp = *buf;
    buf++;

    while (*(buf += jmp) != 0)
        jmp = *buf++;

    return (struct DnsQuery *) ++buf;
}

struct DnsResourceRecord *dns_getrr(unsigned char *buf) {
    unsigned char jmp = *buf;

    if (*buf == 0) // Label length zero (Root)
        return (struct DnsResourceRecord *) ++buf;

    if ((ntohs(*((unsigned short *) buf)) & 0xC000) == 0xC000) // Pointer to label
        return (struct DnsResourceRecord *) (buf + 2);

    buf++;
    // Sequence of labels ending with zero byte or with a pointer
    while (*(buf += jmp) != 0) {
        jmp = *buf;
        if ((ntohs(*((unsigned short *) buf)) & 0xC000) == 0xC000)
            break; // Pointer found!
    }
    return (struct DnsResourceRecord *) ++buf;
}

char *dns_qntodn(struct DnsHeader *dns, unsigned char *qname) {
    int len = 2;
    int alloc = -2;
    int lblsize;
    int idx = 0;
    char *str = NULL;
    char *tmp = NULL;

    if ((str = malloc((size_t) len)) == NULL)
        return NULL;

    if (*qname == 0) {
        str[0] = '.';
        str[1] = '\0';
        return str;
    }

    while (*qname != 0x00) {
        if ((ntohs(*((unsigned short *) (qname))) & 0xC000) == 0xC000)
            qname = (dns->data + (ntohs(*((unsigned short *) qname)) - 0xC000) - 0x0C);

        lblsize = *qname++;
        alloc += lblsize + 1;

        while (lblsize-- > 0) {
            if (idx >= len) {
                len += alloc;
                alloc = 0;
                if ((tmp = realloc(str, (size_t) len)) == NULL) {
                    free(str);
                    return NULL;
                }
                str = tmp;
            }
            str[idx++] = *qname;
            qname++;
        }
        str[idx++] = '.';
    }
    str[idx - 1] = '\0';
    return str;
}
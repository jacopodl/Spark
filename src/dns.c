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

#include <dns.h>

bool dns_qndn_equals(unsigned char *qname, const char *dname) {
    int dnlen = *qname++;

    for (int cursor = 0;; cursor++) {
        if (dnlen-- == 0) {
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

unsigned char *dns_jmpto_answer(struct DnsHeader *dns) {
    int questions = dns->total_questions;
    unsigned char *aptr = dns->data;

    if (dns->total_answers == 0)
        return NULL;

    while (questions-- > 0) {
        aptr = (unsigned char *) dns_getquery(aptr);
        aptr += sizeof(struct DnsQuery);
    }
    return aptr;
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
    unsigned char jmp;

    jmp = *buf;
    buf++;

    while (*(buf += jmp) != 0)
        jmp = *buf++;

    return (struct DnsResourceRecord *) ++buf;
}

char *dns_qntodn(unsigned char *qname) {
    int len = 0;
    int idx = 0;
    char *str = NULL;

    len = (int) ((unsigned char *) dns_getquery(qname) - qname);

    if ((str = malloc((size_t) len - 1)) == NULL)
        return NULL;

    while (*qname != 0x00) {
        len = *qname++;
        for (int i = 0; i < len; i++) {
            str[idx++] = *qname;
            qname++;
        }
        str[idx++] = '.';
    }
    str[idx - 1] = '\0';

    return str;
}
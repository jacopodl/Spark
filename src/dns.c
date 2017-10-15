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

bool dns_dnequals(unsigned char *buf, const char *name) {
    int dnlen = *buf++;

    for (int cursor = 0;; cursor++) {
        if (dnlen-- == 0) {
            dnlen = *buf++;
            if (dnlen != 0 && name[cursor] != '.')
                return false;
            if (dnlen == 0 && name[cursor] == '\0')
                return true;
            continue;
        }
        if (*buf++ != name[cursor] || name[cursor] == '\0')
            return false;
    }
}

char *dns_dntostr(unsigned char *buf) {
    int len = 0;
    int idx = 0;
    char *str = NULL;

    len = (int) ((unsigned char *) dns_getquery(buf) - buf);

    if ((str = malloc((size_t) len - 1)) == NULL)
        return NULL;

    while (*buf != 0x00) {
        len = *buf++;
        for (int i = 0; i < len; i++) {
            str[idx++] = *buf;
            buf++;
        }
        str[idx++] = '.';
    }
    str[idx - 1] = '\0';

    return str;
}

unsigned char *dns_answerptr(struct DnsHeader *dns) {
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

unsigned char *dns_inject_dn(unsigned char *buf, const char *url) {
    int len = 0;
    int ins = 0;
    int i = 0;
    unsigned char count = 0;

    len = (int) strlen(url);

    for (i = 0; i < len; i++) {
        if (url[i] == '.') {
            buf[ins] = count;
            ins = i + 1;
            count = 0;
            continue;
        }
        buf[i + 1] = (unsigned char) url[i];
        count++;
    }

    buf[ins] = count;
    buf[++i] = 0x00;
    return buf + i + 1;
}

unsigned char *dns_strtodn(const char *url, int *rlen) {
    unsigned char *str;

    if ((str = malloc(strlen(url) + 2)) == NULL)
        return NULL;

    dns_inject_dn(str, url);
    *rlen = (int) (strlen(url) + 2);

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
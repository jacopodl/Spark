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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <spkerr.h>
#include <pcap.h>

int spark_pcapnew(struct SpkPcap *pcap, char *filename, unsigned int snaplen, unsigned int dlt) {
    int err = SPKERR_SUCCESS;

    SPKPCAP_FILL_DEFAULT(pcap->header);
    pcap->header.snaplen = snaplen;
    pcap->header.dlt = dlt;

    if ((pcap->filename = strdup(filename)) == NULL)
        return SPKERR_ENOMEM;

    if ((pcap->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC)) < 0) {
        switch (errno) {
            case EACCES:
            case EPERM:
                err = SPKERR_EPERM;
                break;
            case ENOBUFS:
            case ENOMEM:
                err = SPKERR_ENOMEM;
                break;
            default:
                err = SPKERR_ERROR;
        }
        free(pcap->filename);
        return err;
    }

    if (write(pcap->fd, ((char *) &pcap->header), sizeof(struct SpkPcapHdr)) < 0) {
        switch (errno) {
            case EMSGSIZE:
                err = SPKERR_ESIZE;
                break;
            case EINTR:
                err = SPKERR_EINTR;
                break;
            default:
                err = SPKERR_ERROR;
        }
        close(pcap->fd);
        free(pcap->filename);
    }

    return err;
}

int spark_pcapwrite(struct SpkPcap *pcap, unsigned char *buf, unsigned int buflen, struct SpkTimeStamp *ts) {
    struct SpkPcapRecord *record;
    int err = SPKERR_SUCCESS;

    if (buflen > pcap->header.snaplen)
        buflen = pcap->header.snaplen;

    if ((record = malloc(sizeof(struct SpkPcapRecord) + buflen)) == NULL)
        return SPKERR_ENOMEM;

    record->ts_sec = (unsigned int) ts->sec;
    switch (ts->prc) {
        case SPKSTAMP_MICRO:
            if (ts->usec == 0x000F4240) {
                record->ts_usec = 0;
                record->ts_sec++;
                break;
            }
            record->ts_usec = (unsigned int) ts->usec;
            break;
        case SPKSTAMP_NANO:
            if (ts->nsec == 0x3B9ACA00) {
                record->ts_usec = 0;
                record->ts_sec++;
                break;
            }
            record->ts_usec = (unsigned int) ts->nsec;
    }
    record->orig_len = buflen;
    record->incl_len = buflen;

    memcpy(((unsigned char *) record) + sizeof(struct SpkPcapRecord), buf, buflen);

    if (write(pcap->fd, ((unsigned char *) record), sizeof(struct SpkPcapRecord) + buflen) < 0) {
        switch (errno) {
            case EMSGSIZE:
                err = SPKERR_ESIZE;
                break;
            case EINTR:
                err = SPKERR_EINTR;
                break;
            default:
                err = SPKERR_ERROR;
        }
    }

    free(record);
    return err;
}

void spark_pcapclose(struct SpkPcap *pcap) {
    free(pcap->filename);
    close(pcap->fd);
}

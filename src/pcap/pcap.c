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

int spark_pnew(char *filename, unsigned int snaplen, unsigned int dlt, struct SpkPcap **spkpcap) {
    int err = SPKERR_SUCCESS;

    if (filename == NULL || spkpcap == NULL)
        return SPKERR_ERROR;

    if (((*spkpcap) = calloc(1, sizeof(struct SpkPcap))) == NULL)
        return SPKERR_ENOMEM;

    SPKPCAP_FILL_DEFAULT((*spkpcap)->header);
    (*spkpcap)->header.snaplen = snaplen;
    (*spkpcap)->header.dlt = dlt;

    if (((*spkpcap)->filename = strdup(filename)) == NULL) {
        free(*spkpcap);
        return SPKERR_ENOMEM;
    }

    if (((*spkpcap)->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC)) < 0) {
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
        free((*spkpcap)->filename);
        free(*spkpcap);
        return err;
    }

    if (write((*spkpcap)->fd, ((char *) &(*spkpcap)->header), sizeof(struct SpkPcapHdr)) < 0) {
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
        close((*spkpcap)->fd);
        free((*spkpcap)->filename);
        free(*spkpcap);
    }

    return err;
}

int spark_pwrite(struct SpkPcap *spkpcap, unsigned char *buf, unsigned int buflen, struct SpkTimeStamp *ts) {
    struct SpkPcapRecord *record;
    int err = SPKERR_SUCCESS;

    if (spkpcap == NULL)
        return SPKERR_ENINIT;

    if (buflen > spkpcap->header.snaplen)
        buflen = spkpcap->header.snaplen;

    if ((record = malloc(sizeof(struct SpkPcapRecord) + buflen)) == NULL)
        return SPKERR_ENOMEM;

    record->ts_sec = (unsigned int) ts->sec;
    record->ts_usec = (unsigned int) ts->subs;
    switch (ts->prc) {
        case SPKSTAMP_MICRO:
            if (ts->subs >= 0x000F4240) {
                record->ts_usec -= 0x000F4240;
                record->ts_sec++;
            }
            break;
        case SPKSTAMP_NANO:
            if (ts->subs >= 0x3B9ACA00) {
                record->ts_usec -= 0x3B9ACA00;
                record->ts_sec++;
            }
    }
    record->orig_len = buflen;
    record->incl_len = buflen;

    memcpy(((unsigned char *) record) + sizeof(struct SpkPcapRecord), buf, buflen);

    if (write(spkpcap->fd, ((unsigned char *) record), sizeof(struct SpkPcapRecord) + buflen) < 0) {
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

void spark_pclose(struct SpkPcap *spkpcap) {
    if (spkpcap != NULL) {
        close(spkpcap->fd);
        free(spkpcap->filename);
        free(spkpcap);
    }
}
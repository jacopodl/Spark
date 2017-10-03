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
 * @file pcap.h
 * @brief Provides Spark pcap functionalities.
 */

#ifndef LIBSPARK_PCAP_H
#define LIBSPARK_PCAP_H

#include <spksock.h>

#define SPKPCAP_MAGIC           0xA1B2C3D4
#define SPKPCAP_MAGIC_OPPOSITE  0xD4C3B2A1
#define SPKPCAP_SNAPLEN_DEFAULT 65535
#define SPKPCAP_MAJOR  2
#define SPKPCAP_MINOR  4

#define SPKPCAP_FILL_DEFAULT(header)        \
    header.magic_number = SPKPCAP_MAGIC;    \
    header.version_major = SPKPCAP_MAJOR;   \
    header.version_minor = SPKPCAP_MINOR;   \
    header.thiszone = 0;                    \
    header.sigfigs = 0;                     \
    header.snaplen = SPKPCAP_SNAPLEN_DEFAULT

/// @brief Pcap file header.
struct SpkPcapHdr {
    unsigned int magic_number;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int dlt;
};

/// @brief Pcap record header.
struct SpkPcapRecord {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int incl_len;
    unsigned int orig_len;
};

/// @brief Contains information about the currently pcap file.
struct SpkPcap {
    struct SpkPcapHdr header;
    char *filename;
    int fd;
};

/**
 * @brief Create new pcap file.
 * @param filename String contains pcap filename.
 * @param snaplen Max length of snapshot.
 * @param dlt Data-link-type(DLT) value.
 * @param __IN__spkpcap Pointer to SpkPcap structure.
 * @return Upon successful completion, spark_pcapnew() returns SPKERR_SUCCESS.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_pnew(char *filename, unsigned int snaplen, unsigned int dlt, struct SpkPcap **spkpcap);

/**
 * @brief Write on pcap file.
 * @param __IN__spkpcap Pointer to SpkPcap structure.
 * @param buf Buffer contains network packet.
 * @param buflen Length of buffer.
 * @param __IN__ts Pointer to SpkTimeStamp structure.
 * @return Upon successful completion, spark_pcapwrite() returns SPKERR_SUCCESS.
 * Otherwise, a value < 0 shall be returned, you can use spark_strerror to get error message.
 */
int spark_pwrite(struct SpkPcap *spkpcap, unsigned char *buf, unsigned int buflen, struct SpkTimeStamp *ts);

/**
 * @brief Close opened pcap file.
 * @param spkpcap Pointer to SpkPcap structure.
 */
void spark_pclose(struct SpkPcap *spkpcap);

#endif //LIBSPARK_PCAP_H

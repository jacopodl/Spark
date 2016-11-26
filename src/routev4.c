/*
 * Copyright (c) 2016 Jacopo De Luca
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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <routev4.h>

#if defined(__linux__)

bool get_defgateway(char *iface_name, struct netaddr_ip *gateway) {
    char buf[1024];
    char ifa[24];
    int dest;
    unsigned int gate;
    int flags;
    char *line;
    int fd = open(ROUTETABLE, O_RDONLY);
    if (fd == -1)
        return false;
    while (read(fd, buf, 1024) != 0) {
        line = strtok(buf, "\n");
        while (line != NULL) {
            if (sscanf(line, "%s\t%u\t%x\t%u", ifa, &dest, &gate, &flags) != 4) {
                line = strtok(NULL, "\n");
                continue;
            }
            if (iface_name != NULL && strcmp(iface_name, ifa) != 0) {
                line = strtok(NULL, "\n");
                continue;
            }
            if (dest != 0 && flags < 2) {
                line = strtok(NULL, "\n");
                continue;
            }
            gateway->ip = gate;
            close(fd);
            return true;
        }
    }
    close(fd);
    return false;
}

#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#pragma message("get_defgateway not implemented yet! :( ")
bool get_defgateway(char *iface_name, struct netaddr_ip *gateway) {
    // STUB
    return false;
}

#endif
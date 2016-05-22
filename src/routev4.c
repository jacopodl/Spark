/*
* <routev4, part of Spark.>
* Copyright (C) <2015-2016> <Jacopo De Luca>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "routev4.h"

bool get_defgateway(char *iface_name, struct netaddr_ip *gateway) {
    char buff[1024];
    char ifa[24];
    int dest;
    unsigned int gate;
    int flags;
    char *line;
    int fd = open(ROUTETABLE, O_RDONLY);
    if (fd == -1)
        return false;
    while (read(fd, buff, 1024) != 0) {
        line = strtok(buff, "\n");
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
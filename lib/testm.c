#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <string.h>

int
main (int argc, char **argv)
{
	struct ifreq ifr;
	struct sockaddr_dl sdl;
	uint8_t mac[19];
	uint8_t name[IFNAMSIZ];
	int s;

	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
	memset(mac, 0, sizeof(mac));
	mac[0] = ':';
	strncpy(mac + 1, argv[2], strlen(argv[2]));
	sdl.sdl_len = sizeof(sdl);
	link_addr(mac, &sdl);

	bcopy(sdl.sdl_data, ifr.ifr_addr.sa_data, 6);
	ifr.ifr_addr.sa_len = 6;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);

	ioctl(s, SIOCSIFLLADDR, &ifr);

	close(s);
}

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <endian.h>

int NTS_attach_socket(const char *host, int port, int type) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = type;

	struct addrinfo *info;
	if(getaddrinfo(host, NULL, &hints, &info) != 0) {
		return -1;
	}

	for(struct addrinfo *cur = info; cur; cur = cur->ai_next) {
		switch(cur->ai_family) {
			case AF_INET6:
				((struct sockaddr_in6*)cur->ai_addr)->sin6_port = htobe16(port);
				break;
			case AF_INET:
				((struct sockaddr_in*)cur->ai_addr)->sin_port = htobe16(port);
				break;
			default:
				/* try a different sockaddr */
				continue;
		}

		int sock = socket(cur->ai_family, type, 0);
		if(sock < 0) continue;

		if(connect(sock, cur->ai_addr, cur->ai_addrlen) != 0) {
			(void) close(sock);
			continue;
		}

		freeaddrinfo(info);
		return sock;
	}

	freeaddrinfo(info);
	return -2;
}

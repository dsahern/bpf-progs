#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
	char name[32];
	socklen_t optlen = sizeof(name);
	struct sockaddr_in laddr = {
		.sin_family = AF_INET,
		.sin_port = htons(12345),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	unsigned int mark;
	int sd;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("socket");
		return 1;
	}

	name[0] = '\0';
	if (getsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, name, &optlen) < 0)
                perror("setsockopt(SO_BINDTODEVICE)");
	else
		printf("socket bound to dev %s\n", name);

	optlen = sizeof(mark);
	if (getsockopt(sd, SOL_SOCKET, SO_MARK, &mark, &optlen) < 0)
                perror("setsockopt(SO_BINDTODEVICE)");
	else
		printf("socket mark %u\n", mark);


	if (bind(sd, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		perror("bind");
		return 1;
	}
	if (listen(sd, 1) < 0) {
		perror("listen");
		return 1;
	}
	pause();
	close (sd);

	return 0;
}

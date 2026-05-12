
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#define BUF_SIZE 4096

static uint8_t dns_response_example_com[] = {
    /* Header */
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,

    /* Question: example.com */
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
    0x00, 0x01,
    0x00, 0x01,

     /* Answer */
    0xc0, 0x0c,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x3c,
    0x00, 0x04,
    0x5d, 0xb8, 0xd8, 0x22
};

int main(int argc, char *argv[]) {
    int sfd, s;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;
    char buf[BUF_SIZE];
    struct sockaddr_storage local_addr;
    struct sockaddr_in *saddr = &local_addr;

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd == -1){
        printf("cannot open socket %s\n",strerror(errno));
	return -1;
    }

    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(53);
    saddr->sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sfd, saddr, sizeof(*saddr)) != 0){
        printf("Cannot bind %s\n",strerror(errno));
        close(sfd);
    }

    /* Read datagrams and echo them back to sender */

    for (;;) {
        peer_addr_len = sizeof(struct sockaddr_storage);
        nread = recvfrom(
            sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addr_len
        );
        if (nread == -1)
                continue;               /* Ignore failed request */

	memcpy(dns_response_example_com, buf, sizeof(uint16_t));
        if (
            sendto(
                sfd,
                dns_response_example_com,
                sizeof(dns_response_example_com),
                0,
                (struct sockaddr *) &peer_addr,
                peer_addr_len
            ) != sizeof(dns_response_example_com)
        ) {
            fprintf(stderr, "Error sending response\n");
        }
    }
}


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#define BUF_SIZE 4096
#if 1
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
#else
const uint8_t dns_response_example_com[] = {
    // --- HEADER (12 bytes) ---
    0xAA, 0xAA, // Transaction ID (0xAAAA)
    0x84, 0x00, // Flags: Standard response, NoError, Authoritative, No Recursion
    0x00, 0x01, // Questions: 1
    0x00, 0x01, // Answer RRs: 1 (SOA)
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0

    // --- QUESTION SECTION ---
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 
    0x03, 'c', 'o', 'm', 
    0x00,       // Null terminator for domain
    0x00, 0x06, // Type: SOA
    0x00, 0x01, // Class: IN

    // --- ANSWER SECTION (SOA) ---
    0xc0, 0x0c, // Name: Pointer to question (offset 12)
    0x00, 0x06, // Type: SOA
    0x00, 0x01, // Class: IN
    0x00, 0x00, 0x0e, 0x10, // TTL: 3600 (1 hour)
    0x00, 0x24, // RDLENGTH: 36 bytes (Data length)

    // SOA Data
    // MNAME: ns1.example.com (3ns1 + 7example + 3com + 0)
    0x03, 'n', 's', '1', 0xc0, 0x10, // ns1.example.com
    // RNAME: hostmaster.example.com
    0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r', 0xc0, 0x10, 
    0x66, 0x6e, 0x1a, 0x50, // Serial: 1717581392
    0x00, 0x00, 0x0e, 0x10, // Refresh: 3600
    0x00, 0x00, 0x03, 0x84, // Retry: 900
    0x00, 0x09, 0x3a, 0x80, // Expire: 604800
    0x00, 0x00, 0x0e, 0x10  // Minimum TTL: 3600
};
#endif

typedef struct {
	char ip_to_bind[20];
	int core_idx;
}params_t;

void *core_n_thread(void *arg){
	int sfd, s;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char buf[BUF_SIZE];
	struct sockaddr_storage local_addr;
	struct sockaddr_in *saddr = &local_addr;
	params_t* params = (params_t*)arg;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd == -1){
		printf("cannot open socket %s\n",strerror(errno));
		return -1;
	}

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(53 + params->core_idx);
	saddr->sin_addr.s_addr = inet_addr(params->ip_to_bind);
	if (bind(sfd, saddr, sizeof(*saddr)) != 0){
		printf("Cannot bind %s\n",strerror(errno));
		close(sfd);
	}

	/* Read datagrams and echo them back to sender */

	for (;;) {
		peer_addr_len = sizeof(struct sockaddr_storage);
		nread = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addr_len);
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

int main(int argc, char *argv[]) {
	long n_procs = sysconf(_SC_NPROCESSORS_ONLN);
	pthread_t threads[n_procs];
	for (int core_idx = 0; core_idx < n_procs; core_idx++){
		pthread_t thread;
		params_t *params = (params_t*)calloc(1, sizeof(params_t));
		strcpy(params->ip_to_bind, argv[1]);
		params->core_idx = core_idx;
		if (pthread_create(&thread, NULL, core_n_thread, params)){
			printf("Cannot create a thread %d %s\n",core_idx,strerror(errno));
		}else{
			threads[core_idx] = thread;
		}
	}
	for (int core_idx = 0; core_idx < n_procs; core_idx++){
		pthread_join(threads[core_idx], NULL);
	}
}

/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"


#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
struct config cfg = {
	.ifindex   = -1,
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",	 required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

struct xsk_umem_config mem_cfg = {
    .fill_size = NUM_FRAMES / 2,
    .comp_size = NUM_FRAMES / 2,
    .frame_size = FRAME_SIZE,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = 0 // Can use XSK_UMEM__USES_NEED_WAKEUP for performance
};

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &mem_cfg);
	if (ret) {
		errno = -ret;
		printf("%s %d\n",__FILE__,__LINE__);
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	} else {
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

#if 1
static const uint8_t dns_response_example_com[] = {
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
    0x81, 0x80, // Flags: Standard response, NoError, Authoritative, No Recursion
    0x00, 0x01, // Questions: 1
    0x00, 0x01, // Answer RRs: 1 (SOA)
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0

    // --- QUESTION SECTION ---
     /* Question: example.com */
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
    0x00, 0x01,
    0x00, 0x01,

    // --- ANSWER SECTION (SOA) ---
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x01, // Type: SOA
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

#include <stdint.h>
//#include <netinet/udp.h>
#include <arpa/inet.h>
//#include <netinet/ip.h>

#include <arpa/inet.h>

/* IPv4 UDP checksum over pseudo-header + UDP header (check=0) + payload (RFC 768 / 1071). */
 static void recalculate_full_udp_csum_ipv4(const struct iphdr *iph, struct udphdr *udph){
            uint32_t sum = 0;
            __u32 saddr = ntohl(iph->saddr);
            __u32 daddr = ntohl(iph->daddr);

            sum += (saddr >> 16) & 0xffff;
            sum += saddr & 0xffff;
            sum += (daddr >> 16) & 0xffff;
            sum += daddr & 0xffff;
            sum += IPPROTO_UDP;
            sum += ntohs(udph->len);

            udph->check = 0;

            sum += ntohs(udph->source);
            sum += ntohs(udph->dest);
            sum += ntohs(udph->len);
            sum += ntohs(udph->check);

            uint8_t *payload = (uint8_t *)(udph + 1);
            size_t ulen = ntohs(udph->len);
            size_t hlen = sizeof(struct udphdr);

            if (ulen < hlen)
                    return;

            size_t plen = ulen - hlen;
            size_t i;

            for (i = 0; i + 1 < plen; i += 2)
                    sum += ((uint16_t)payload[i] << 8) | payload[i + 1];
            if (i < plen)
                    sum += (uint16_t)payload[i] << 8;

            while (sum >> 16)
                    sum = (sum & 0xffff) + (sum >> 16);

            uint16_t csum = (uint16_t)~sum;

            if (csum == 0)
                    csum = 0xffff;
            udph->check = htons(csum);
 }

 void update_packet_length_and_csums(struct iphdr *iph, struct udphdr *udph,
                                        uint16_t old_udp_len, uint16_t new_udp_len) {
    
        // Calculate the raw delta between lengths
        int32_t len_delta = (int32_t)new_udp_len - (int32_t)old_udp_len;
        if (len_delta == 0) return; // No change needed
    
        // ==========================================
        // STEP 1: UPDATE L3 IP HEADER CHECKSUM
        // ==========================================
        uint16_t old_ip_tot_len = ntohs(iph->tot_len);
        uint16_t new_ip_tot_len = old_ip_tot_len + len_delta;
    
        // Update the field in network byte order
        iph->tot_len = htons(new_ip_tot_len);
    
        // Incremental IP Checksum Update (RFC 1624)
        uint32_t ip_csum = ~ntohs(iph->check) & 0xFFFF;
        ip_csum += (uint16_t)(~old_ip_tot_len);
        ip_csum += new_ip_tot_len;
        while (ip_csum >> 16) {
            ip_csum = (ip_csum & 0xFFFF) + (ip_csum >> 16);
        }
        iph->check = htons((uint16_t)(~ip_csum));
    
        // ==========================================
        // STEP 2: UPDATE L4 UDP HEADER & CHECKSUM
        // ==========================================
        udph->len = htons(new_udp_len);
        recalculate_full_udp_csum_ipv4(iph, udph);
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	/* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */
	int ret;
	uint32_t tx_idx = 0;
	uint8_t tmp_mac[ETH_ALEN];

	struct hdr_cursor nh;
	int nh_type, ip_type = 0;
	struct iphdr *iph;
	struct udphdr *udphdr;
	nh.pos = pkt;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, pkt + len, &eth);
	if (nh_type < 0)
		return false;

	// Copy Source MAC to temporary storage
	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	// Copy Destination MAC to Source MAC
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	// Copy temporary storage to Destination MAC
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		ip_type = parse_ip6hdr(&nh, pkt + len, &ip6h);
		struct in6_addr tmp_ip;

		// Copy Source IP to temporary storage
		memcpy(&tmp_ip, &ip6h->saddr, sizeof(struct in6_addr));
		// Copy Destination IP to Source IP
		memcpy(&ip6h->saddr, &ip6h->daddr, sizeof(struct in6_addr));
		// Copy temporary storage to Destination IP
		memcpy(&ip6h->daddr, &tmp_ip, sizeof(struct in6_addr));

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, pkt + len, &iph);
	}
	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, pkt + len, &udphdr) < 0) {
			return false;
		}
		if (bpf_ntohs(udphdr->dest) == 53){
			ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			if (ret != 1) {
				/* No more transmit slots, drop the packet */
				return false;
			}
			uint8_t *dns = (uint8_t *)(udphdr + 1);
			uint16_t client_tx_id = *(uint16_t *)dns;

			// Overwrite the first 2 bytes of your static reply template in-memory 
			// // (Directly updates the '0x12, 0x34' placeholder to match the client)
//			*(uint16_t *)dns = client_tx_id; 
			memcpy(&dns[2], &dns_response_example_com[2], sizeof(dns_response_example_com)-2);
			if (nh_type == bpf_htons(ETH_P_IP)){
				uint32_t tmp = iph->daddr;
				iph->daddr = iph->saddr;
				iph->saddr = tmp;
//				recalculate_full_ip_csum(iph);
			}else{
			}
			uint16_t temp_port = udphdr->source;
			udphdr->source = udphdr->dest;
			udphdr->dest = temp_port;
			update_packet_length_and_csums(iph, udphdr, ntohs(udphdr->len), sizeof(dns_response_example_com)+8);
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = (dns - pkt) + sizeof(dns_response_example_com);
			xsk_ring_prod__submit(&xsk->tx, 1);
			xsk->outstanding_tx++;
			return true;
		}
	}else{
		return false;
	}

	return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

	}

	xsk_ring_cons__release(&xsk->rx, rcvd);

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
}

static void exit_application(int signal)
{
	int err;

	cfg.unload_all = true;
	err = do_unload(&cfg);
	if (err) {
		fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
			cfg.ifname, err);
	}

	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	int err;
	char errmsg[1024];

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
		DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
			.open_filename = cfg.filename,
		);
		struct bpf_map *map;
		custom_xsk = true;
		if (cfg.progname[0] != 0)
			xdp_opts.prog_name = cfg.progname;

		prog = xdp_program__create(&xdp_opts);
		err = libxdp_get_error(prog);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}

		err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
				cfg.ifname, errmsg, err);
			return err;
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
		xsk_map_fd = bpf_map__fd(map);
		if (xsk_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 *
	 * NOTE: since kernel v5.11, eBPF maps allocations are not tracked
	 * through the process anymore. Now, eBPF maps are accounted to the
	 * current cgroup of which the process that created the map is part of
	 * (assuming the kernel was built with CONFIG_MEMCG).
	 *
	 * Therefore, you should ensure an appropriate memory.max setting on
	 * the cgroup (via sysfs, for example) instead of relying on rlimit.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = ((NUM_FRAMES * FRAME_SIZE)/2097152)*2097152;
#if 0
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
#else
	packet_buffer = mmap(NULL, packet_buffer_size, PROT_READ | PROT_WRITE, 
			                  MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (packet_buffer == NULL){
		printf("cannot allocate mapped memory\n");
		exit(EXIT_FAILURE);
	}
#endif

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	free(packet_buffer);

	return EXIT_OK;
}

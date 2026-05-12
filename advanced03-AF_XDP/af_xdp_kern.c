/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp_dns")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int index = ctx->rx_queue_index;

	struct hdr_cursor nh;
	int nh_type, ip_type = 0;
	struct udphdr *udphdr;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		ip_type = parse_ip6hdr(&nh, data_end, &ip6h);

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;

		ip_type = parse_iphdr(&nh, data_end, &iph);
	}
	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		if (bpf_ntohs(udphdr->dest) == 53){
			if (bpf_map_lookup_elem(&xsks_map, &index))
				return bpf_redirect_map(&xsks_map, index, 0);
		}
	}else{
		goto out;
	}
 out:
//	return xdp_stats_record_action(ctx, action)	

	return action;
}

char _license[] SEC("license") = "GPL";

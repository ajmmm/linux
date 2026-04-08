// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, __u64);
} server_map SEC(".maps");

static __always_inline int parse_udp_dport(struct __sk_buff *skb, __be16 *dport)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *uh;

	if (eth + 1 > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	iph = data + sizeof(*eth);
	if (iph + 1 > data_end)
		return -1;
	if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
		return -1;

	uh = (void *)iph + sizeof(*iph);
	if (uh + 1 > data_end)
		return -1;

	*dport = uh->dest;
	return 0;
}

SEC("tc")
int tc_netkit_sk_assign(struct __sk_buff *skb)
{
	struct bpf_sock *sk;
	const int zero = 0;
	__be16 dport;
	int ret;

	if (parse_udp_dport(skb, &dport))
		return TCX_PASS;
	if (dport != bpf_htons(4321))
		return TCX_PASS;

	sk = bpf_map_lookup_elem(&server_map, &zero);
	if (!sk)
		return TCX_DROP;

	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);

	return ret ? TCX_DROP : TCX_PASS;
}

char __license[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>
#include <stddef.h>
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
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} server_map SEC(".maps");

char _license[] SEC("license") = "GPL";

static __always_inline int assign_udp_socket(struct __sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
	struct iphdr *iph;
	struct udphdr *uh;
	struct bpf_sock *sk;
	void *data_end = (void *)(long)skb->data_end;
	const int zero = 0;
	int ret;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_SHOT;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_SHOT;
	if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
		return TC_ACT_OK;

	uh = (void *)iph + sizeof(*iph);
	if ((void *)(uh + 1) > data_end)
		return TC_ACT_SHOT;
	if (uh->dest != bpf_htons(4321))
		return TC_ACT_OK;

	sk = bpf_map_lookup_elem(&server_map, &zero);
	if (!sk)
		return TC_ACT_SHOT;

	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("tc")
int sk_assign_drop(struct __sk_buff *skb)
{
	int ret = assign_udp_socket(skb);

	return ret == TC_ACT_OK ? TC_ACT_SHOT : ret;
}

SEC("tc")
int sk_assign_pass(struct __sk_buff *skb)
{
	return assign_udp_socket(skb);
}

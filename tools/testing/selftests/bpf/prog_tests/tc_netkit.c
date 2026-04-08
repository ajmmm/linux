// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */
#include <uapi/linux/if_link.h>
#include <net/if.h>
#include <test_progs.h>

#define netkit_peer "nk0"
#define netkit_name "nk1"

#define ping_addr_neigh		0x0a000002 /* 10.0.0.2 */
#define ping_addr_noneigh	0x0a000003 /* 10.0.0.3 */

#include "test_tc_link.skel.h"
#include "test_tc_peer.skel.h"
#include "test_tc_netkit_sk_assign.skel.h"
#include "network_helpers.h"
#include "netlink_helpers.h"
#include "tc_helpers.h"

#define NETKIT_HEADROOM	32
#define NETKIT_TAILROOM	8

#define MARK		42
#define PRIO		0xeb9f
#define ICMP_ECHO	8

#define NETKIT_NS_FOO "ns_tc_netkit_foo"
#define NETKIT_NS_BAR "ns_tc_netkit_bar"
#define NETKIT_A_DEV "nk1"
#define NETKIT_A_PEER "nk0"
#define NETKIT_B_DEV "mk1"
#define NETKIT_B_PEER "mk0"
#define NETKIT_A_IP 0x0a000001 /* 10.0.0.1 */
#define NETKIT_A_PEER_IP 0x0a000002 /* 10.0.0.2 */
#define NETKIT_B_IP 0x0a000101 /* 10.0.1.1 */
#define NETKIT_B_PEER_IP 0x0a000102 /* 10.0.1.2 */

#define FLAG_ADJUST_ROOM (1 << 0)
#define FLAG_SAME_NETNS  (1 << 1)

struct icmphdr {
	__u8		type;
	__u8		code;
	__sum16		checksum;
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
};

struct iplink_req {
	struct nlmsghdr  n;
	struct ifinfomsg i;
	char             buf[1024];
};

static int create_netkit_named(const char *prim, const char *peer,
			       int mode, int policy, int peer_policy,
			       int *ifindex, int scrub, int peer_scrub,
			       __u32 flags)
{
	struct rtnl_handle rth = { .fd = -1 };
	struct iplink_req req = {};
	struct rtattr *linkinfo, *data;
	const char *type = "netkit";
	int err;

	err = rtnl_open(&rth, 0);
	if (!ASSERT_OK(err, "open_rtnetlink"))
		return err;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;

	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, prim, strlen(prim));
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, type, strlen(type));
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_POLICY, policy);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_PEER_POLICY, peer_policy);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_SCRUB, scrub);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_PEER_SCRUB, peer_scrub);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, mode);
	if (flags & FLAG_ADJUST_ROOM) {
		addattr16(&req.n, sizeof(req), IFLA_NETKIT_HEADROOM, NETKIT_HEADROOM);
		addattr16(&req.n, sizeof(req), IFLA_NETKIT_TAILROOM, NETKIT_TAILROOM);
	}
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);

	err = rtnl_talk(&rth, &req.n, NULL);
	ASSERT_OK(err, "talk_rtnetlink");
	rtnl_close(&rth);
	*ifindex = if_nametoindex(prim);

	ASSERT_GT(*ifindex, 0, "retrieve_ifindex");
	return err;
}

static int create_netkit(int mode, int policy, int peer_policy, int *ifindex,
			 int scrub, int peer_scrub, __u32 flags)
{
	int err;

	err = create_netkit_named(netkit_name, netkit_peer, mode, policy,
				  peer_policy, ifindex, scrub, peer_scrub,
				  flags);
	if (err)
		return err;

	ASSERT_OK(system("ip netns add foo"), "create netns");
	ASSERT_OK(system("ip link set dev " netkit_name " up"),
			 "up primary");
	ASSERT_OK(system("ip addr add dev " netkit_name " 10.0.0.1/24"),
			 "addr primary");

	if (mode == NETKIT_L3) {
		ASSERT_EQ(system("ip link set dev " netkit_name
				 " addr ee:ff:bb:cc:aa:dd 2> /dev/null"), 512,
				 "set hwaddress");
	} else {
		ASSERT_OK(system("ip link set dev " netkit_name
				 " addr ee:ff:bb:cc:aa:dd"),
				 "set hwaddress");
	}
	if (flags & FLAG_SAME_NETNS) {
		ASSERT_OK(system("ip link set dev " netkit_peer " up"),
				 "up peer");
		ASSERT_OK(system("ip addr add dev " netkit_peer " 10.0.0.2/24"),
				 "addr peer");
	} else {
		ASSERT_OK(system("ip link set " netkit_peer " netns foo"),
				 "move peer");
		ASSERT_OK(system("ip netns exec foo ip link set dev "
				 netkit_peer " up"), "up peer");
		ASSERT_OK(system("ip netns exec foo ip addr add dev "
				 netkit_peer " 10.0.0.2/24"), "addr peer");
	}
	return err;
}

static void move_netkit(void)
{
	ASSERT_OK(system("ip link set " netkit_peer " netns foo"),
			 "move peer");
	ASSERT_OK(system("ip netns exec foo ip link set dev "
			 netkit_peer " up"), "up peer");
	ASSERT_OK(system("ip netns exec foo ip addr add dev "
			 netkit_peer " 10.0.0.2/24"), "addr peer");
}

static void destroy_netkit(void)
{
	ASSERT_OK(system("ip link del dev " netkit_name), "del primary");
	ASSERT_OK(system("ip netns del foo"), "delete netns");
	ASSERT_EQ(if_nametoindex(netkit_name), 0, netkit_name "_ifindex");
}

static int __send_icmp(__u32 dest)
{
	int sock, ret, mark = MARK, prio = PRIO;
	struct sockaddr_in addr;
	struct icmphdr icmp;

	ret = write_sysctl("/proc/sys/net/ipv4/ping_group_range", "0 0");
	if (!ASSERT_OK(ret, "write_sysctl(net.ipv4.ping_group_range)"))
		return ret;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (!ASSERT_GE(sock, 0, "icmp_socket"))
		return -errno;

	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			 netkit_name, strlen(netkit_name) + 1);
	if (!ASSERT_OK(ret, "setsockopt(SO_BINDTODEVICE)"))
		goto out;

	ret = setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	if (!ASSERT_OK(ret, "setsockopt(SO_MARK)"))
		goto out;

	ret = setsockopt(sock, SOL_SOCKET, SO_PRIORITY,
			 &prio, sizeof(prio));
	if (!ASSERT_OK(ret, "setsockopt(SO_PRIORITY)"))
		goto out;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(dest);

	memset(&icmp, 0, sizeof(icmp));
	icmp.type = ICMP_ECHO;
	icmp.echo.id = 1234;
	icmp.echo.sequence = 1;

	ret = sendto(sock, &icmp, sizeof(icmp), 0,
		     (struct sockaddr *)&addr, sizeof(addr));
	if (!ASSERT_GE(ret, 0, "icmp_sendto"))
		ret = -errno;
	else
		ret = 0;
out:
	close(sock);
	return ret;
}

static int send_icmp(void)
{
	return __send_icmp(ping_addr_neigh);
}

static int send_udp_to_peer(__u16 port, const void *buf, size_t len)
{
	struct sockaddr_in addr = {};
	int sock, ret;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(sock, 0, "udp_socket"))
		return -errno;

	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			 netkit_name, strlen(netkit_name) + 1);
	if (!ASSERT_OK(ret, "setsockopt(SO_BINDTODEVICE)"))
		goto out;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ping_addr_neigh);

	ret = sendto(sock, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (!ASSERT_EQ(ret, len, "udp_sendto"))
		ret = ret < 0 ? -errno : -EIO;
	else
		ret = 0;
out:
	close(sock);
	return ret;
}

static int send_udp_to_dev(const char *dev, __u32 dest, __u16 port,
			   const void *buf, size_t len)
{
	struct sockaddr_in addr = {};
	int sock, ret;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(sock, 0, "udp_socket"))
		return -errno;

	ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			 dev, strlen(dev) + 1);
	if (!ASSERT_OK(ret, "setsockopt(SO_BINDTODEVICE)"))
		goto out;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(dest);

	ret = sendto(sock, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (!ASSERT_EQ(ret, len, "udp_sendto"))
		ret = ret < 0 ? -errno : -EIO;
	else
		ret = 0;
out:
	close(sock);
	return ret;
}

static int recv_udp(int fd, void *buf, size_t len)
{
	ssize_t ret;

	ret = recvfrom(fd, buf, len, 0, NULL, NULL);
	if (!ASSERT_EQ(ret, len, "udp_recvfrom"))
		return ret < 0 ? -errno : -EIO;
	return 0;
}

static void cleanup_redirect_peer_topology(void)
{
	system("ip link del dev " NETKIT_A_DEV " 2>/dev/null");
	system("ip link del dev " NETKIT_B_DEV " 2>/dev/null");
	system("ip netns del " NETKIT_NS_FOO " 2>/dev/null");
	system("ip netns del " NETKIT_NS_BAR " 2>/dev/null");
}

void serial_test_tc_netkit_basic(void)
{
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	__u32 prog_ids[2], link_ids[2];
	__u32 pid1, pid2, lid1, lid2;
	struct test_tc_link *skel;
	struct bpf_link *link;
	int err, ifindex;

	err = create_netkit(NETKIT_L2, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, 0);
	if (err)
		return;

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1,
		  BPF_NETKIT_PRIMARY), 0, "tc1_attach_type");
	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc2,
		  BPF_NETKIT_PEER), 0, "tc2_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	pid1 = id_from_prog_fd(bpf_program__fd(skel->progs.tc1));
	pid2 = id_from_prog_fd(bpf_program__fd(skel->progs.tc2));

	ASSERT_NEQ(pid1, pid2, "prog_ids_1_2");

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	ASSERT_EQ(skel->bss->seen_tc1, false, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc1 = link;

	lid1 = id_from_link_fd(bpf_link__fd(skel->links.tc1));

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	optq.prog_ids = prog_ids;
	optq.link_ids = link_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, BPF_NETKIT_PRIMARY, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	link = bpf_program__attach_netkit(skel->progs.tc2, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc2 = link;

	lid2 = id_from_link_fd(bpf_link__fd(skel->links.tc2));
	ASSERT_NEQ(lid1, lid2, "link_ids_1_2");

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 1);

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, BPF_NETKIT_PEER, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid2, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid2, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc2, true, "seen_tc2");
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);
	destroy_netkit();
}

static void serial_test_tc_netkit_multi_links_target(int mode, int target)
{
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	__u32 prog_ids[3], link_ids[3];
	__u32 pid1, pid2, lid1, lid2;
	struct test_tc_link *skel;
	struct bpf_link *link;
	int err, ifindex;

	err = create_netkit(mode, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, 0);
	if (err)
		return;

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1,
		  target), 0, "tc1_attach_type");
	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc2,
		  target), 0, "tc2_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	pid1 = id_from_prog_fd(bpf_program__fd(skel->progs.tc1));
	pid2 = id_from_prog_fd(bpf_program__fd(skel->progs.tc2));

	ASSERT_NEQ(pid1, pid2, "prog_ids_1_2");

	assert_mprog_count_ifindex(ifindex, target, 0);

	ASSERT_EQ(skel->bss->seen_tc1, false, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, false, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc1 = link;

	lid1 = id_from_link_fd(bpf_link__fd(skel->links.tc1));

	assert_mprog_count_ifindex(ifindex, target, 1);

	optq.prog_ids = prog_ids;
	optq.link_ids = link_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, target, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	LIBBPF_OPTS_RESET(optl,
		.flags = BPF_F_BEFORE,
		.relative_fd = bpf_program__fd(skel->progs.tc1),
	);

	link = bpf_program__attach_netkit(skel->progs.tc2, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc2 = link;

	lid2 = id_from_link_fd(bpf_link__fd(skel->links.tc2));
	ASSERT_NEQ(lid1, lid2, "link_ids_1_2");

	assert_mprog_count_ifindex(ifindex, target, 2);

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, target, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 2, "count");
	ASSERT_EQ(optq.revision, 3, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid2, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid2, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], pid1, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], lid1, "link_ids[1]");
	ASSERT_EQ(optq.prog_ids[2], 0, "prog_ids[2]");
	ASSERT_EQ(optq.link_ids[2], 0, "link_ids[2]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, true, "seen_tc2");
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, target, 0);
	destroy_netkit();
}

void serial_test_tc_netkit_multi_links(void)
{
	serial_test_tc_netkit_multi_links_target(NETKIT_L2, BPF_NETKIT_PRIMARY);
	serial_test_tc_netkit_multi_links_target(NETKIT_L3, BPF_NETKIT_PRIMARY);
	serial_test_tc_netkit_multi_links_target(NETKIT_L2, BPF_NETKIT_PEER);
	serial_test_tc_netkit_multi_links_target(NETKIT_L3, BPF_NETKIT_PEER);
}

static void serial_test_tc_netkit_multi_opts_target(int mode, int target)
{
	LIBBPF_OPTS(bpf_prog_attach_opts, opta);
	LIBBPF_OPTS(bpf_prog_detach_opts, optd);
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	__u32 pid1, pid2, fd1, fd2;
	__u32 prog_ids[3];
	struct test_tc_link *skel;
	int err, ifindex;

	err = create_netkit(mode, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, 0);
	if (err)
		return;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	fd1 = bpf_program__fd(skel->progs.tc1);
	fd2 = bpf_program__fd(skel->progs.tc2);

	pid1 = id_from_prog_fd(fd1);
	pid2 = id_from_prog_fd(fd2);

	ASSERT_NEQ(pid1, pid2, "prog_ids_1_2");

	assert_mprog_count_ifindex(ifindex, target, 0);

	ASSERT_EQ(skel->bss->seen_tc1, false, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, false, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	err = bpf_prog_attach_opts(fd1, ifindex, target, &opta);
	if (!ASSERT_EQ(err, 0, "prog_attach"))
		goto cleanup;

	assert_mprog_count_ifindex(ifindex, target, 1);

	optq.prog_ids = prog_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, target, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_fd1;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	LIBBPF_OPTS_RESET(opta,
		.flags = BPF_F_BEFORE,
		.relative_fd = fd1,
	);

	err = bpf_prog_attach_opts(fd2, ifindex, target, &opta);
	if (!ASSERT_EQ(err, 0, "prog_attach"))
		goto cleanup_fd1;

	assert_mprog_count_ifindex(ifindex, target, 2);

	memset(prog_ids, 0, sizeof(prog_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, target, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_fd2;

	ASSERT_EQ(optq.count, 2, "count");
	ASSERT_EQ(optq.revision, 3, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid2, "prog_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], pid1, "prog_ids[1]");
	ASSERT_EQ(optq.prog_ids[2], 0, "prog_ids[2]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, true, "seen_eth");
	ASSERT_EQ(skel->bss->seen_tc2, true, "seen_tc2");

cleanup_fd2:
	err = bpf_prog_detach_opts(fd2, ifindex, target, &optd);
	ASSERT_OK(err, "prog_detach");
	assert_mprog_count_ifindex(ifindex, target, 1);
cleanup_fd1:
	err = bpf_prog_detach_opts(fd1, ifindex, target, &optd);
	ASSERT_OK(err, "prog_detach");
	assert_mprog_count_ifindex(ifindex, target, 0);
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, target, 0);
	destroy_netkit();
}

void serial_test_tc_netkit_multi_opts(void)
{
	serial_test_tc_netkit_multi_opts_target(NETKIT_L2, BPF_NETKIT_PRIMARY);
	serial_test_tc_netkit_multi_opts_target(NETKIT_L3, BPF_NETKIT_PRIMARY);
	serial_test_tc_netkit_multi_opts_target(NETKIT_L2, BPF_NETKIT_PEER);
	serial_test_tc_netkit_multi_opts_target(NETKIT_L3, BPF_NETKIT_PEER);
}

void serial_test_tc_netkit_device(void)
{
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	__u32 prog_ids[2], link_ids[2];
	__u32 pid1, pid2, lid1;
	struct test_tc_link *skel;
	struct bpf_link *link;
	int err, ifindex, ifindex2;

	err = create_netkit(NETKIT_L3, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, FLAG_SAME_NETNS);
	if (err)
		return;

	ifindex2 = if_nametoindex(netkit_peer);
	ASSERT_NEQ(ifindex, ifindex2, "ifindex_1_2");

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1,
		  BPF_NETKIT_PRIMARY), 0, "tc1_attach_type");
	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc2,
		  BPF_NETKIT_PEER), 0, "tc2_attach_type");
	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc3,
		  BPF_NETKIT_PRIMARY), 0, "tc3_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	pid1 = id_from_prog_fd(bpf_program__fd(skel->progs.tc1));
	pid2 = id_from_prog_fd(bpf_program__fd(skel->progs.tc2));

	ASSERT_NEQ(pid1, pid2, "prog_ids_1_2");

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	ASSERT_EQ(skel->bss->seen_tc1, false, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc1 = link;

	lid1 = id_from_link_fd(bpf_link__fd(skel->links.tc1));

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	optq.prog_ids = prog_ids;
	optq.link_ids = link_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, BPF_NETKIT_PRIMARY, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc2, false, "seen_tc2");

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex2, BPF_NETKIT_PRIMARY, &optq);
	ASSERT_EQ(err, -EACCES, "prog_query_should_fail");

	err = bpf_prog_query_opts(ifindex2, BPF_NETKIT_PEER, &optq);
	ASSERT_EQ(err, -EACCES, "prog_query_should_fail");

	link = bpf_program__attach_netkit(skel->progs.tc2, ifindex2, &optl);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	link = bpf_program__attach_netkit(skel->progs.tc3, ifindex2, &optl);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);
	destroy_netkit();
}

static void serial_test_tc_netkit_neigh_links_target(int mode, int target)
{
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	__u32 prog_ids[2], link_ids[2];
	__u32 pid1, lid1;
	struct test_tc_link *skel;
	struct bpf_link *link;
	int err, ifindex;

	err = create_netkit(mode, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, 0);
	if (err)
		return;

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1,
		  BPF_NETKIT_PRIMARY), 0, "tc1_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	pid1 = id_from_prog_fd(bpf_program__fd(skel->progs.tc1));

	assert_mprog_count_ifindex(ifindex, target, 0);

	ASSERT_EQ(skel->bss->seen_tc1, false, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, false, "seen_eth");

	link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc1 = link;

	lid1 = id_from_link_fd(bpf_link__fd(skel->links.tc1));

	assert_mprog_count_ifindex(ifindex, target, 1);

	optq.prog_ids = prog_ids;
	optq.link_ids = link_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(ifindex, target, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(__send_icmp(ping_addr_noneigh), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true /* L2: ARP */, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_eth, mode == NETKIT_L3, "seen_eth");
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, target, 0);
	destroy_netkit();
}

void serial_test_tc_netkit_neigh_links(void)
{
	serial_test_tc_netkit_neigh_links_target(NETKIT_L2, BPF_NETKIT_PRIMARY);
	serial_test_tc_netkit_neigh_links_target(NETKIT_L3, BPF_NETKIT_PRIMARY);
}

static void serial_test_tc_netkit_pkt_type_mode(int mode)
{
	LIBBPF_OPTS(bpf_netkit_opts, optl_nk);
	LIBBPF_OPTS(bpf_tcx_opts, optl_tcx);
	int err, ifindex, ifindex2;
	struct test_tc_link *skel;
	struct bpf_link *link;

	err = create_netkit(mode, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, FLAG_SAME_NETNS);
	if (err)
		return;

	ifindex2 = if_nametoindex(netkit_peer);
	ASSERT_NEQ(ifindex, ifindex2, "ifindex_1_2");

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc1,
		  BPF_NETKIT_PRIMARY), 0, "tc1_attach_type");
	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc7,
		  BPF_TCX_INGRESS), 0, "tc7_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	assert_mprog_count_ifindex(ifindex,  BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex2, BPF_TCX_INGRESS, 0);

	link = bpf_program__attach_netkit(skel->progs.tc1, ifindex, &optl_nk);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc1 = link;

	assert_mprog_count_ifindex(ifindex,  BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex2, BPF_TCX_INGRESS, 0);

	link = bpf_program__attach_tcx(skel->progs.tc7, ifindex2, &optl_tcx);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc7 = link;

	assert_mprog_count_ifindex(ifindex,  BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex2, BPF_TCX_INGRESS, 1);

	move_netkit();

	tc_skel_reset_all_seen(skel);
	skel->bss->set_type = true;
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc1, true, "seen_tc1");
	ASSERT_EQ(skel->bss->seen_tc7, true, "seen_tc7");

	ASSERT_EQ(skel->bss->seen_host,  true, "seen_host");
	ASSERT_EQ(skel->bss->seen_mcast, true, "seen_mcast");
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex,  BPF_NETKIT_PRIMARY, 0);
	destroy_netkit();
}

void serial_test_tc_netkit_pkt_type(void)
{
	serial_test_tc_netkit_pkt_type_mode(NETKIT_L2);
	serial_test_tc_netkit_pkt_type_mode(NETKIT_L3);
}

static void serial_test_tc_netkit_scrub_type(int scrub, bool room)
{
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	struct test_tc_link *skel;
	struct bpf_link *link;
	int err, ifindex;

	err = create_netkit(NETKIT_L2, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, scrub, scrub,
			    room ? FLAG_ADJUST_ROOM : 0);
	if (err)
		return;

	skel = test_tc_link__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc8,
		  BPF_NETKIT_PRIMARY), 0, "tc8_attach_type");

	err = test_tc_link__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	ASSERT_EQ(skel->bss->seen_tc8, false, "seen_tc8");

	link = bpf_program__attach_netkit(skel->progs.tc8, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.tc8 = link;

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 1);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);

	tc_skel_reset_all_seen(skel);
	ASSERT_EQ(send_icmp(), 0, "icmp_pkt");

	ASSERT_EQ(skel->bss->seen_tc8, true, "seen_tc8");
	ASSERT_EQ(skel->bss->mark, scrub == NETKIT_SCRUB_NONE ? MARK : 0, "mark");
	ASSERT_EQ(skel->bss->prio, scrub == NETKIT_SCRUB_NONE ? PRIO : 0, "prio");
	ASSERT_EQ(skel->bss->headroom, room ? NETKIT_HEADROOM : 0, "headroom");
	ASSERT_EQ(skel->bss->tailroom, room ? NETKIT_TAILROOM : 0, "tailroom");
cleanup:
	test_tc_link__destroy(skel);

	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PRIMARY, 0);
	assert_mprog_count_ifindex(ifindex, BPF_NETKIT_PEER, 0);
	destroy_netkit();
}

void serial_test_tc_netkit_scrub(void)
{
	serial_test_tc_netkit_scrub_type(NETKIT_SCRUB_DEFAULT, false);
	serial_test_tc_netkit_scrub_type(NETKIT_SCRUB_NONE, true);
}

void serial_test_tc_netkit_sk_assign(void)
{
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	struct sockaddr_in *addr4;
	struct network_helper_opts opts = {
		.timeout_ms = 3000,
	};
	struct test_tc_netkit_sk_assign *skel;
	struct sockaddr_storage addr = {};
	struct nstoken *nstoken = NULL;
	struct bpf_link *link;
	char buf[] = "netkit";
	char recv_buf[sizeof(buf)];
	const int zero = 0;
	int server = -1;
	int err, ifindex;

	err = create_netkit(NETKIT_L3, NETKIT_PASS, NETKIT_PASS,
			    &ifindex, NETKIT_SCRUB_DEFAULT,
			    NETKIT_SCRUB_DEFAULT, 0);
	if (err)
		return;

	nstoken = open_netns("foo");
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto cleanup;

	addr4 = (struct sockaddr_in *)&addr;
	memset(addr4, 0, sizeof(*addr4));
	addr4->sin_family = AF_INET;
	addr4->sin_port = htons(1234);
	addr4->sin_addr.s_addr = htonl(ping_addr_neigh);
	server = start_server_addr(SOCK_DGRAM, &addr, sizeof(struct sockaddr_in), &opts);
	if (!ASSERT_OK_FD(server, "start_server_addr"))
		goto cleanup;

	close_netns(nstoken);
	nstoken = NULL;

	skel = test_tc_netkit_sk_assign__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	ASSERT_EQ(bpf_program__set_expected_attach_type(skel->progs.tc_netkit_sk_assign,
		  BPF_NETKIT_PEER), 0, "sk_assign_attach_type");

	err = test_tc_netkit_sk_assign__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup_skel;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.server_map), &zero, &server, 0);
	if (!ASSERT_OK(err, "map_update"))
		goto cleanup_skel;

	link = bpf_program__attach_netkit(skel->progs.tc_netkit_sk_assign, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup_skel;

	skel->links.tc_netkit_sk_assign = link;

	err = send_udp_to_peer(4321, buf, sizeof(buf));
	if (!ASSERT_OK(err, "send_udp_to_peer"))
		goto cleanup_skel;

	err = recv_udp(server, recv_buf, sizeof(recv_buf));
	if (!ASSERT_OK(err, "recv_udp"))
		goto cleanup_skel;

	ASSERT_EQ(memcmp(buf, recv_buf, sizeof(buf)), 0, "payload");

cleanup_skel:
	test_tc_netkit_sk_assign__destroy(skel);
cleanup:
	if (nstoken)
		close_netns(nstoken);
	if (server >= 0)
		close(server);
	destroy_netkit();
}

void serial_test_tc_netkit_redirect_peer(void)
{
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	struct network_helper_opts opts = {
		.timeout_ms = 3000,
	};
	struct test_tc_peer *skel = NULL;
	struct sockaddr_storage addr = {};
	struct sockaddr_in *addr4;
	struct nstoken *nstoken = NULL;
	struct bpf_link *link;
	char buf[] = "redir";
	char recv_buf[sizeof(buf)];
	int ifindex_a = 0, ifindex_b = 0;
	int server = -1;
	int err;

	cleanup_redirect_peer_topology();

	err = create_netkit_named(NETKIT_A_DEV, NETKIT_A_PEER,
				  NETKIT_L3, NETKIT_PASS, NETKIT_PASS,
				  &ifindex_a, NETKIT_SCRUB_DEFAULT,
				  NETKIT_SCRUB_DEFAULT, 0);
	if (!ASSERT_OK(err, "create_netkit_a"))
		goto cleanup;
	err = create_netkit_named(NETKIT_B_DEV, NETKIT_B_PEER,
				  NETKIT_L3, NETKIT_PASS, NETKIT_PASS,
				  &ifindex_b, NETKIT_SCRUB_DEFAULT,
				  NETKIT_SCRUB_DEFAULT, 0);
	if (!ASSERT_OK(err, "create_netkit_b"))
		goto cleanup;

	ASSERT_OK(system("ip netns add " NETKIT_NS_FOO), "create netns foo");
	ASSERT_OK(system("ip netns add " NETKIT_NS_BAR), "create netns bar");

	ASSERT_OK(system("ip link set dev " NETKIT_A_DEV " up"), "up nk1");
	ASSERT_OK(system("ip link set dev " NETKIT_B_DEV " up"), "up mk1");
	ASSERT_OK(system("ip addr add dev " NETKIT_A_DEV " 10.0.0.1/24"), "addr nk1");
	ASSERT_OK(system("ip addr add dev " NETKIT_B_DEV " 10.0.1.1/24"), "addr mk1");
	ASSERT_OK(system("ip route add 10.0.1.2/32 dev " NETKIT_A_DEV), "route to mk0");

	ASSERT_OK(system("ip link set " NETKIT_A_PEER " netns " NETKIT_NS_FOO), "move nk0");
	ASSERT_OK(system("ip netns exec " NETKIT_NS_FOO " ip link set dev " NETKIT_A_PEER " up"), "up nk0");
	ASSERT_OK(system("ip netns exec " NETKIT_NS_FOO " ip addr add dev " NETKIT_A_PEER " 10.0.0.2/24"), "addr nk0");

	ASSERT_OK(system("ip link set " NETKIT_B_PEER " netns " NETKIT_NS_BAR), "move mk0");
	ASSERT_OK(system("ip netns exec " NETKIT_NS_BAR " ip link set dev " NETKIT_B_PEER " up"), "up mk0");
	ASSERT_OK(system("ip netns exec " NETKIT_NS_BAR " ip addr add dev " NETKIT_B_PEER " 10.0.1.2/24"), "addr mk0");

	nstoken = open_netns(NETKIT_NS_BAR);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto cleanup;

	addr4 = (struct sockaddr_in *)&addr;
	memset(addr4, 0, sizeof(*addr4));
	addr4->sin_family = AF_INET;
	addr4->sin_port = htons(1234);
	addr4->sin_addr.s_addr = htonl(NETKIT_B_PEER_IP);
	server = start_server_addr(SOCK_DGRAM, &addr, sizeof(struct sockaddr_in), &opts);
	if (!ASSERT_OK_FD(server, "start_server_addr"))
		goto cleanup;

	close_netns(nstoken);
	nstoken = NULL;

	skel = test_tc_peer__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->rodata->IFINDEX_DST = ifindex_b;
	err = bpf_program__set_expected_attach_type(skel->progs.tc_src,
						    BPF_NETKIT_PEER);
	if (!ASSERT_OK(err, "attach_type"))
		goto cleanup;

	err = test_tc_peer__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	link = bpf_program__attach_netkit(skel->progs.tc_src, ifindex_a, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel->links.tc_src = link;

	err = send_udp_to_dev(NETKIT_A_DEV, NETKIT_B_PEER_IP, 1234, buf, sizeof(buf));
	if (!ASSERT_OK(err, "send_udp_to_dev"))
		goto cleanup;

	err = recv_udp(server, recv_buf, sizeof(recv_buf));
	if (!ASSERT_OK(err, "recv_udp"))
		goto cleanup;

	ASSERT_EQ(memcmp(buf, recv_buf, sizeof(buf)), 0, "payload");

cleanup:
	test_tc_peer__destroy(skel);
	if (nstoken)
		close_netns(nstoken);
	if (server >= 0)
		close(server);
	cleanup_redirect_peer_topology();
}

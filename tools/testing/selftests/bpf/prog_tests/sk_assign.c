// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook
// Copyright (c) 2019 Cloudflare
// Copyright (c) 2020 Isovalent, Inc.
/*
 * Test that the socket assign program is able to redirect traffic towards a
 * socket, regardless of whether the port or address destination of the traffic
 * matches the port.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_sk_assign_lifetime.skel.h"
#include "test_progs.h"
#include "network_helpers.h"

#define BIND_PORT 1234
#define CONNECT_PORT 4321
#define TEST_DADDR (0xC0A80203)
#define NS_SELF "/proc/self/ns/net"
#define SERVER_MAP_PATH "/sys/fs/bpf/tc/globals/server_map"
#define SRC_DEV "sk_assign_src0"
#define DST_DEV "sk_assign_dst0"
#define SRC_ADDR "10.0.0.1"
#define DST_ADDR "10.0.0.2"

static int stop, duration;

static bool
attach_tc_filter(bool ingress)
{
	char tc_version[128];
	char tc_cmd[BUFSIZ];
	char *prog;
	FILE *tc;

	/* Check whether tc is built with libbpf. */
	tc = popen("tc -V", "r");
	if (CHECK_FAIL(!tc))
		return false;
	if (CHECK_FAIL(!fgets(tc_version, sizeof(tc_version), tc))) {
		pclose(tc);
		return false;
	}
	if (strstr(tc_version, ", libbpf "))
		prog = "test_sk_assign_libbpf.bpf.o";
	else
		prog = "test_sk_assign.bpf.o";
	if (CHECK_FAIL(pclose(tc)))
		return false;

	sprintf(tc_cmd, "%s %s %s %s %s", ingress ?
		       "tc filter add dev lo ingress bpf" :
		       "tc filter add dev lo egress bpf",
		       "direct-action object-file", prog,
		       "section tc",
		       (env.verbosity < VERBOSE_VERY) ? " 2>/dev/null" : "verbose");
	if (CHECK(system(tc_cmd), "BPF load failed;",
		  "run with -vv for more info\n"))
		return false;

	return true;
}

static bool
configure_stack(bool ingress)
{
	/* Move to a new networking namespace */
	if (CHECK_FAIL(unshare(CLONE_NEWNET)))
		return false;

	/* Configure necessary links, routes */
	if (CHECK_FAIL(system("ip link set dev lo up")))
		return false;
	if (CHECK_FAIL(system("ip route add local default dev lo")))
		return false;
	if (CHECK_FAIL(system("ip -6 route add local default dev lo")))
		return false;

	/* Load qdisc, BPF program */
	if (CHECK_FAIL(system("tc qdisc add dev lo clsact")))
		return false;
	return attach_tc_filter(ingress);
}

static in_port_t
get_port(int fd)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	in_port_t port = 0;

	if (CHECK_FAIL(getsockname(fd, (struct sockaddr *)&ss, &slen)))
		return port;

	switch (ss.ss_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)&ss)->sin_port;
		break;
	case AF_INET6:
		port = ((struct sockaddr_in6 *)&ss)->sin6_port;
		break;
	default:
		CHECK(1, "Invalid address family", "%d\n", ss.ss_family);
	}
	return port;
}

static ssize_t
rcv_msg(int srv_client, int type)
{
	char buf[BUFSIZ];

	if (type == SOCK_STREAM)
		return read(srv_client, &buf, sizeof(buf));
	else
		return recvfrom(srv_client, &buf, sizeof(buf), 0, NULL, NULL);
}

static int
run_test(int server_fd, const struct sockaddr *addr, socklen_t len, int type)
{
	int client = -1, srv_client = -1;
	char buf[] = "testing";
	in_port_t port;
	int ret = 1;

	client = connect_to_addr(type, (struct sockaddr_storage *)addr, len, NULL);
	if (client == -1) {
		perror("Cannot connect to server");
		goto out;
	}

	if (type == SOCK_STREAM) {
		srv_client = accept(server_fd, NULL, NULL);
		if (CHECK_FAIL(srv_client == -1)) {
			perror("Can't accept connection");
			goto out;
		}
	} else {
		srv_client = server_fd;
	}
	if (CHECK_FAIL(write(client, buf, sizeof(buf)) != sizeof(buf))) {
		perror("Can't write on client");
		goto out;
	}
	if (CHECK_FAIL(rcv_msg(srv_client, type) != sizeof(buf))) {
		perror("Can't read on server");
		goto out;
	}

	port = get_port(srv_client);
	if (CHECK_FAIL(!port))
		goto out;
	/* SOCK_STREAM is connected via accept(), so the server's local address
	 * will be the CONNECT_PORT rather than the BIND port that corresponds
	 * to the listen socket. SOCK_DGRAM on the other hand is connectionless
	 * so we can't really do the same check there; the server doesn't ever
	 * create a socket with CONNECT_PORT.
	 */
	if (type == SOCK_STREAM &&
	    CHECK(port != htons(CONNECT_PORT), "Expected", "port %u but got %u",
		  CONNECT_PORT, ntohs(port)))
		goto out;
	else if (type == SOCK_DGRAM &&
		 CHECK(port != htons(BIND_PORT), "Expected",
		       "port %u but got %u", BIND_PORT, ntohs(port)))
		goto out;

	ret = 0;
out:
	close(client);
	if (srv_client != server_fd)
		close(srv_client);
	if (ret)
		WRITE_ONCE(stop, 1);
	return ret;
}

static void
prepare_addr(struct sockaddr *addr, int family, __u16 port, bool rewrite_addr)
{
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;

	switch (family) {
	case AF_INET:
		addr4 = (struct sockaddr_in *)addr;
		memset(addr4, 0, sizeof(*addr4));
		addr4->sin_family = family;
		addr4->sin_port = htons(port);
		if (rewrite_addr)
			addr4->sin_addr.s_addr = htonl(TEST_DADDR);
		else
			addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		break;
	case AF_INET6:
		addr6 = (struct sockaddr_in6 *)addr;
		memset(addr6, 0, sizeof(*addr6));
		addr6->sin6_family = family;
		addr6->sin6_port = htons(port);
		addr6->sin6_addr = in6addr_loopback;
		if (rewrite_addr)
			addr6->sin6_addr.s6_addr32[3] = htonl(TEST_DADDR);
		break;
	default:
		fprintf(stderr, "Invalid family %d", family);
	}
}

struct test_sk_cfg {
	const char *name;
	int family;
	struct sockaddr *addr;
	socklen_t len;
	int type;
	bool rewrite_addr;
	bool ingress;
};

#define TEST(NAME, FAMILY, TYPE, REWRITE, INGRESS)			\
{									\
	.name = NAME,							\
	.family = FAMILY,						\
	.addr = (FAMILY == AF_INET) ? (struct sockaddr *)&addr4		\
				    : (struct sockaddr *)&addr6,	\
	.len = (FAMILY == AF_INET) ? sizeof(addr4) : sizeof(addr6),	\
	.type = TYPE,							\
	.rewrite_addr = REWRITE,					\
	.ingress = INGRESS,						\
}

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

static bool configure_tc_dev(const char *dev)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
	return ASSERT_OK(system(cmd), "link_up");
}

static bool update_server_map(struct test_sk_assign_lifetime *skel, int fd)
{
	const int zero = 0;

	return ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.server_map),
					     &zero, &fd, 0), "map_update");
}

static bool run_drop_after_assign_test(bool ingress)
{
	struct test_sk_assign_lifetime *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = 100,
	};
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char buf[32];
	const char payload[] = "drop-after-assign";
	int orig_net = -1, server_fd = -1, client_fd = -1;
	ssize_t err;
	bool ok = false;

	orig_net = open(NS_SELF, O_RDONLY);
	if (!ASSERT_GE(orig_net, 0, "open_self_net"))
		return false;

	if (CHECK_FAIL(unshare(CLONE_NEWNET)))
		goto out;
	if (!ASSERT_OK(system("ip link set dev lo up"), "link_up"))
		goto out;
	if (!ASSERT_OK(system("ip route add local default dev lo"), "route_v4"))
		goto out;

	skel = test_sk_assign_lifetime__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	if (!ASSERT_OK(tc_prog_attach("lo",
				      ingress ? bpf_program__fd(skel->progs.sk_assign_drop) : -1,
				      ingress ? -1 : bpf_program__fd(skel->progs.sk_assign_drop)),
		       "tc_prog_attach"))
		goto out;

	server_fd = start_server_str(AF_INET, SOCK_DGRAM, "127.0.0.1", BIND_PORT, &opts);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto out;
	if (!update_server_map(skel, server_fd))
		goto out;

	if (!ASSERT_OK(make_sockaddr(AF_INET, "127.0.0.1", CONNECT_PORT, &addr, &addrlen),
		       "make_sockaddr"))
		goto out;
	client_fd = connect_to_addr(SOCK_DGRAM, &addr, addrlen, &opts);
	if (!ASSERT_GE(client_fd, 0, "connect"))
		goto out;

	if (!ASSERT_EQ(write(client_fd, payload, sizeof(payload)), sizeof(payload), "write"))
		goto out;

	err = recvfrom(server_fd, buf, sizeof(buf), 0, NULL, NULL);
	if (!ASSERT_EQ(err, -1, "recv_timeout"))
		goto out;
	if (!ASSERT_EQ(errno, EAGAIN, "recv_errno"))
		goto out;

	ok = true;
out:
	close_fd(&client_fd);
	close_fd(&server_fd);
	test_sk_assign_lifetime__destroy(skel);
	if (orig_net >= 0) {
		if (!ASSERT_OK(setns(orig_net, CLONE_NEWNET), "restore_netns"))
			ok = false;
		close(orig_net);
	}
	return ok;
}

static bool run_egress_orphan_test(void)
{
	struct test_sk_assign_lifetime *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = 100,
	};
	struct nstoken *token = NULL;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char src_ns[64] = "sk_assign_src";
	char dst_ns[64] = "sk_assign_dst";
	char buf[32];
	const char payload[] = "egress-orphan";
	int assigned_fd = -1, client_fd = -1, remote_fd = -1;
	ssize_t err;
	bool ok = false;
	char cmd[256];

	if (!ASSERT_OK(append_tid(src_ns, sizeof(src_ns)), "append_src_tid"))
		return false;
	if (!ASSERT_OK(append_tid(dst_ns, sizeof(dst_ns)), "append_dst_tid"))
		return false;

	snprintf(cmd, sizeof(cmd), "ip netns del %s >/dev/null 2>&1", src_ns);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "ip netns del %s >/dev/null 2>&1", dst_ns);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "ip link del %s >/dev/null 2>&1", SRC_DEV);
	system(cmd);

	if (!ASSERT_OK(make_netns(src_ns), "make_src_ns"))
		return false;
	if (!ASSERT_OK(make_netns(dst_ns), "make_dst_ns"))
		goto out;

	snprintf(cmd, sizeof(cmd),
		 "ip link add %s netns %s type veth peer name %s netns %s",
		 SRC_DEV, src_ns, DST_DEV, dst_ns);
	if (!ASSERT_OK(system(cmd), "add_veth"))
		goto out;

	snprintf(cmd, sizeof(cmd), "ip -n %s addr add %s/24 dev %s", src_ns, SRC_ADDR, SRC_DEV);
	if (!ASSERT_OK(system(cmd), "src_addr"))
		goto out;
	snprintf(cmd, sizeof(cmd), "ip -n %s link set dev %s up", src_ns, SRC_DEV);
	if (!ASSERT_OK(system(cmd), "src_up"))
		goto out;
	snprintf(cmd, sizeof(cmd), "ip -n %s addr add %s/24 dev %s", dst_ns, DST_ADDR, DST_DEV);
	if (!ASSERT_OK(system(cmd), "dst_addr"))
		goto out;
	snprintf(cmd, sizeof(cmd), "ip -n %s link set dev %s up", dst_ns, DST_DEV);
	if (!ASSERT_OK(system(cmd), "dst_up"))
		goto out;
	snprintf(cmd, sizeof(cmd), "ip -n %s route add %s/32 dev %s", src_ns, DST_ADDR, SRC_DEV);
	if (!ASSERT_OK(system(cmd), "src_route"))
		goto out;

	token = open_netns(src_ns);
	if (!ASSERT_OK_PTR(token, "open_src_ns"))
		goto out;
	if (!configure_tc_dev(SRC_DEV))
		goto out;

	skel = test_sk_assign_lifetime__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;
	if (!ASSERT_OK(tc_prog_attach(SRC_DEV, -1, bpf_program__fd(skel->progs.sk_assign_pass)),
		       "tc_prog_attach"))
		goto out;

	assigned_fd = start_server_str(AF_INET, SOCK_DGRAM, SRC_ADDR, BIND_PORT, &opts);
	if (!ASSERT_GE(assigned_fd, 0, "start_assigned_server"))
		goto out;
	if (!update_server_map(skel, assigned_fd))
		goto out;

	if (!ASSERT_OK(make_sockaddr(AF_INET, DST_ADDR, CONNECT_PORT, &addr, &addrlen),
		       "make_dst_addr"))
		goto out;
	client_fd = connect_to_addr(SOCK_DGRAM, &addr, addrlen, &opts);
	if (!ASSERT_GE(client_fd, 0, "connect"))
		goto out;

	close_netns(token);
	token = open_netns(dst_ns);
	if (!ASSERT_OK_PTR(token, "open_dst_ns"))
		goto out;

	remote_fd = start_server_str(AF_INET, SOCK_DGRAM, DST_ADDR, CONNECT_PORT, &opts);
	if (!ASSERT_GE(remote_fd, 0, "start_remote_server"))
		goto out;

	close_netns(token);
	token = NULL;

	if (!ASSERT_EQ(write(client_fd, payload, sizeof(payload)), sizeof(payload), "write"))
		goto out;

	err = recvfrom(remote_fd, buf, sizeof(buf), 0, NULL, NULL);
	if (!ASSERT_EQ(err, sizeof(payload), "recv_remote"))
		goto out;

	err = recvfrom(assigned_fd, buf, sizeof(buf), 0, NULL, NULL);
	if (!ASSERT_EQ(err, -1, "assigned_recv_timeout"))
		goto out;
	if (!ASSERT_EQ(errno, EAGAIN, "assigned_recv_errno"))
		goto out;

	ok = true;
out:
	if (token)
		close_netns(token);
	close_fd(&assigned_fd);
	close_fd(&client_fd);
	close_fd(&remote_fd);
	test_sk_assign_lifetime__destroy(skel);
	snprintf(cmd, sizeof(cmd), "ip link del %s >/dev/null 2>&1", SRC_DEV);
	system(cmd);
	remove_netns(src_ns);
	remove_netns(dst_ns);
	return ok;
}

void test_sk_assign(void)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct test_sk_cfg tests[] = {
		TEST("ipv4 tcp port redir ingress", AF_INET, SOCK_STREAM, false, true),
		TEST("ipv4 tcp addr redir ingress", AF_INET, SOCK_STREAM, true, true),
		TEST("ipv6 tcp port redir ingress", AF_INET6, SOCK_STREAM, false, true),
		TEST("ipv6 tcp addr redir ingress", AF_INET6, SOCK_STREAM, true, true),
		TEST("ipv4 udp port redir ingress", AF_INET, SOCK_DGRAM, false, true),
		TEST("ipv4 udp addr redir ingress", AF_INET, SOCK_DGRAM, true, true),
		TEST("ipv6 udp port redir ingress", AF_INET6, SOCK_DGRAM, false, true),
		TEST("ipv6 udp addr redir ingress", AF_INET6, SOCK_DGRAM, true, true),
		TEST("ipv4 tcp port redir egress", AF_INET, SOCK_STREAM, false, false),
		TEST("ipv4 tcp addr redir egress", AF_INET, SOCK_STREAM, true, false),
		TEST("ipv6 tcp port redir egress", AF_INET6, SOCK_STREAM, false, false),
		TEST("ipv6 tcp addr redir egress", AF_INET6, SOCK_STREAM, true, false),
		TEST("ipv4 udp port redir egress", AF_INET, SOCK_DGRAM, false, false),
		TEST("ipv4 udp addr redir egress", AF_INET, SOCK_DGRAM, true, false),
		TEST("ipv6 udp port redir egress", AF_INET6, SOCK_DGRAM, false, false),
		TEST("ipv6 udp addr redir egress", AF_INET6, SOCK_DGRAM, true, false),
	};
	__s64 server = -1;
	int server_map;
	int self_net;
	int i;
	bool ingress = true;

	self_net = open(NS_SELF, O_RDONLY);
	if (CHECK_FAIL(self_net < 0)) {
		perror("Unable to open "NS_SELF);
		return;
	}

	if (!configure_stack(ingress)) {
		perror("configure_stack");
		goto cleanup;
	}

	server_map = bpf_obj_get(SERVER_MAP_PATH);
	if (CHECK_FAIL(server_map < 0)) {
		perror("Unable to open " SERVER_MAP_PATH);
		goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(tests) && !READ_ONCE(stop); i++) {
		struct test_sk_cfg *test = &tests[i];
		const struct sockaddr *addr;
		const int zero = 0;
		int err;

		if (!test__start_subtest(test->name))
			continue;

		if (test->ingress != ingress) {
			close(server_map);
			if (CHECK_FAIL(system("tc qdisc del dev lo clsact")))
				goto cleanup;
			if (CHECK_FAIL(system("tc qdisc add dev lo clsact")))
				goto cleanup;
			ingress = test->ingress;
			if (!attach_tc_filter(ingress)) {
				perror("attach_tc_filter");
				goto cleanup;
			}
			server_map = bpf_obj_get(SERVER_MAP_PATH);
			if (CHECK_FAIL(server_map < 0)) {
				perror("Unable to open " SERVER_MAP_PATH);
				goto cleanup;
			}
		}

		prepare_addr(test->addr, test->family, BIND_PORT, false);
		addr = (const struct sockaddr *)test->addr;
		server = start_server_addr(test->type,
					   (const struct sockaddr_storage *)addr,
					   test->len, NULL);
		if (server == -1)
			goto close;

		err = bpf_map_update_elem(server_map, &zero, &server, BPF_ANY);
		if (CHECK_FAIL(err)) {
			perror("Unable to update server_map");
			goto close;
		}

		/* connect to unbound ports */
		prepare_addr(test->addr, test->family, CONNECT_PORT,
			     test->rewrite_addr);
		if (run_test(server, addr, test->len, test->type))
			goto close;

		close(server);
		server = -1;
	}

close:
	close(server);
	close(server_map);

	if (!READ_ONCE(stop) && test__start_subtest("udp drop after assign ingress") &&
	    !run_drop_after_assign_test(true))
		goto cleanup;

	if (!READ_ONCE(stop) && test__start_subtest("udp drop after assign egress") &&
	    !run_drop_after_assign_test(false))
		goto cleanup;

	if (!READ_ONCE(stop) && test__start_subtest("udp egress orphan scrub") &&
	    !run_egress_orphan_test())
		goto cleanup;
cleanup:
	if (CHECK_FAIL(unlink(SERVER_MAP_PATH)))
		perror("Unable to unlink " SERVER_MAP_PATH);
	if (CHECK_FAIL(setns(self_net, CLONE_NEWNET)))
		perror("Failed to setns("NS_SELF")");
	close(self_net);
}

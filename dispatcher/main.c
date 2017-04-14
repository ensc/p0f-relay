/*	--*- c -*--
 * Copyright (C) 2011 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include <getopt.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <p0f-relay/api.h>
#include <p0f-relay/rpc.h>
#include <common/daemonize.h>
#include <common/io.h>

#ifndef DISPATCHER_SOCKFILE
#  define DISPATCHER_SOCKFILE	LOCALSTATEDIR "/run/p0f-dispatcher/sock"
#endif

#ifndef DISPATCHER_USER
#  define DISPATCHER_USER	"p0f-dispatcher"
#endif

#ifndef DEFAULT_PORT
#  define DEFAULT_PORT	"2342"
#endif

enum {
	CMD_HELP = 0x1000,
	CMD_VERSION,
	CMD_DAEMON,
	CMD_SIGSTOP,
	CMD_PIDFILE,
	CMD_STRICT,
	CMD_CHROOT,
};

struct p0f_mapping {
	unsigned char			af_family;
	union {
		struct in_addr		ip4;
		struct in6_addr		ip6;
	}				dstX_addr;
	char const			*node;
	char const			*service;
};

struct cmdline_options {
	struct daemonize_options	daemon;
	char const			*socket_file;

	struct p0f_mapping		*mappings;
	size_t				num_mappings;
	unsigned int			max_queries;

	bool				strict_mode;
	unsigned int			prefer_ip4:1;
	unsigned int			prefer_ip6:1;
};

static struct option const CMDLINE_OPTIONS[] = {
	{ "help",        no_argument,       NULL, CMD_HELP },
	{ "version",     no_argument,       NULL, CMD_VERSION },
	{ "daemon",      no_argument,       NULL, CMD_DAEMON },
	{ "sigstop",     no_argument,       NULL, CMD_SIGSTOP },
	{ "strict",      no_argument,       NULL, CMD_STRICT },
	{ "chroot",      required_argument, NULL, CMD_CHROOT },
	{ "pidfile",     required_argument, NULL, CMD_PIDFILE },
	{ "user",        required_argument, NULL, 'u' },
	{ NULL, 0, NULL, 0}
};

static void show_help(void)
{
	puts("Usage: p0f-dispatch [--pidfile <filename>] [--daemon|--sigstop]\n"
	     "  [--user|-u <username>] [--socket|-s <socket>]\n"
	     "  [--map|-m <ipv4>=<p0f-connector>]*");
	exit(0);
}

static void show_version(void)
{
	puts("p0f-dispatch " VERSION " -- p0f dispatcher agent\n\n"
	     "Copyright (C) 2011 Enrico Scholz\n"
	     "This program is free software; you may redistribute it under the terms of\n"
	     "the GNU General Public License.  This program has absolutely no warranty.");
	exit(0);
}

static int add_mapping(struct cmdline_options *opts, char const *mstr)
{
	char		*tmp = strdupa(mstr);
	char const	*from = tmp;
	char		*to = strchr(tmp, '=');
	char		*port;
	struct p0f_mapping	*new_mappings;
	struct p0f_mapping	m;


	if (to == NULL || to[1] == '\0') {
		fputs("missing p0f-connect address\n", stderr);
		return -1;
	}

	if (to == tmp) {
		fputs("missing src address\n", stderr);
		return -1;
	}

	*to++ = '\0';
	port = strchr(to, ':');
	if (port != NULL && port[1] == '\0') {
		fputs("bad port specifier\n", stderr);
		return -1;
	}

	if (port != NULL) {
		port[0] = '\0';
		++port;
	} else {
		port = DEFAULT_PORT;
	}

	if (strncmp(from, "ipv4:", 5) == 0) {
		m.af_family = AF_INET;
		from += 5;
	} else if (strncmp(from, "ipv6:", 5) == 0) {
		m.af_family = AF_INET6;
		from += 5;
	} else if (strchr(from, ':') != NULL) {
		m.af_family = AF_INET6;
	} else {
		m.af_family = AF_INET;
	}

	if (inet_pton(m.af_family, from, &m.dstX_addr) < 0) {
		perror("inet_pton()");
		return -1;
	}

	m.node = strdup(to);
	m.service = strdup(port);

	if (!m.node || !m.service) {
		perror("strdup()");

		free((void *)m.service);
		free((void *)m.node);
		return -1;
	}

	new_mappings = realloc(opts->mappings,
			       sizeof(opts->mappings[0]) * (opts->num_mappings + 1));

	if (!new_mappings) {
		perror("realloc()");

		free((void *)m.service);
		free((void *)m.node);
		return -1;
	}

	new_mappings[opts->num_mappings++] = m;
	opts->mappings = new_mappings;

	return 0;
}

static int open_p0f_socket(struct cmdline_options const *opts)
{
	struct sockaddr_un	addr = {
		.sun_family = AF_UNIX
	};
	int			s;

	if (strlen(opts->socket_file) + 1 > sizeof addr.sun_path) {
		fputs("socket filename too long\n", stderr);
		return -1;
	}

	strncpy(addr.sun_path, opts->socket_file, sizeof addr.sun_path);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket(<p0f-socket>)");
		return -1;
	}

	if (bind(s, (void const *)&addr, sizeof addr) < 0) {
		perror("bind(<p0f-socket>)");
		close(s);
		return -1;
	}

	if (listen(s, 10) < 0) {
		perror("listen(<p0f-socket>)");
		close(s);
		return -1;
	}

	return s;
}

static void handle_sigchld(int num)
{
	(void)num;
}

static int set_sighandlers(void)
{
	struct sigaction	sa[] = {
		{
			.sa_handler = handle_sigchld,
			.sa_flags = 0
		},
	};

	if (sigaction(SIGCHLD, &sa[0], NULL) < 0) {
		perror("sigaction()");
		return -1;
	}

	return 0;
}

static sa_family_t p0f_addr_to_sa_family(u8 addr_type)
{
	switch (addr_type) {
	case P0F_ADDR_IPV4:
		return AF_INET;
	case P0F_ADDR_IPV6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static struct p0f_mapping const *find_mapping(struct cmdline_options const *opts,
					      struct p0f_api_query const *q,
					      uint8_t const *host)
{
	size_t		i;

	if (!host && opts->num_mappings == 1)
		return &opts->mappings[0];

	for (i = 0; i < opts->num_mappings; ++i) {
		size_t		sa_len;

		if (p0f_addr_to_sa_family(q->addr_type) !=
		    opts->mappings[i].af_family)
			continue;

		switch (opts->mappings[i].af_family) {
		case AF_INET:
			sa_len = sizeof opts->mappings[i].dstX_addr.ip4;
			break;

		case AF_INET6:
			sa_len = sizeof opts->mappings[i].dstX_addr.ip6;
			break;

		default:
			continue;
		}

		if (memcmp(host, &opts->mappings[i].dstX_addr, sa_len) == 0)
			return &opts->mappings[i];
	}

	return NULL;
}

union response_local {
	struct p0f_api_response	r;
} __packed;

#define _copy_fields(a, b, field) do { \
		static_assert(sizeof (a)->field == sizeof (b)->field, \
			      "differently sized attributes"); \
		memcpy((a)->field, (b)->field, sizeof (a)->field); \
	} while(0)

static ssize_t receive_response(int s, union response_local *dst)
{
	union {
		be32_t				type;
		struct p0f_rpc_response		r;
	} __packed				msg;
	be32_t					len;
	ssize_t					dst_len;

	if (recv_all(s, &len, sizeof len) != 0 ||
	    recv_all(s, &msg, be32toh(len)) != 0)
		return -1;

	switch (be32toh(msg.type)) {
	case 0:
		dst_len       = sizeof dst->r;

		dst->r = (struct p0f_api_response) {
			.magic		= P0F_RESP_MAGIC,
			.status		= be32toh(msg.r.status),

			.first_seen	= be32toh(msg.r.first_seen),
			.last_seen	= be32toh(msg.r.last_seen),
			.total_conn	= be32toh(msg.r.total_conn),

			.uptime_min	= be32toh(msg.r.uptime_min),
			.up_mod_days	= be32toh(msg.r.up_mod_days),

			.last_nat	= be32toh(msg.r.last_nat),
			.last_chg	= be32toh(msg.r.last_chg),

			.distance	= be16toh(msg.r.distance),

			.bad_sw		= msg.r.bad_sw,
			.os_match_q	= msg.r.os_match_q,
		};

		_copy_fields(&dst->r, &msg.r, os_name);
		_copy_fields(&dst->r, &msg.r, os_flavor);
		_copy_fields(&dst->r, &msg.r, http_name);
		_copy_fields(&dst->r, &msg.r, http_flavor);
		_copy_fields(&dst->r, &msg.r, link_type);
		_copy_fields(&dst->r, &msg.r, language);

		break;

	default:
		return -1;
	}

	return dst_len;
}

static void handle_query(struct cmdline_options const *opts, int s)
{
	struct p0f_api_query		query;
	uint8_t				addr_host[16];
	uint8_t const			*host_ptr;
	struct p0f_mapping const	*mapping;
	int				server_sock = -1;
	union response_local		resp;
	ssize_t				resp_len = -1;

	if (recv_all(s, &query, sizeof query) != 0)
		goto err;

	switch (query.magic) {
	case P0F_QUERY_MAGIC:
		host_ptr = NULL;
		break;

	case P0F_QUERY_MAGIC_EXT:
		if (!recv_all(s, &addr_host, sizeof addr_host))
			goto err;
		host_ptr = addr_host;
		break;

	default:
		goto err;
	}

	mapping = find_mapping(opts, &query, host_ptr);
	if (mapping != NULL) {
		struct addrinfo const		hints = {
			.ai_family	=  (opts->prefer_ip4 ? AF_INET :
					    opts->prefer_ip6 ? AF_INET6 :
					    AF_UNSPEC),
			.ai_socktype	=  SOCK_STREAM,
			.ai_flags	=  0,
			.ai_protocol	=  0,
		};
		int				rc;
		struct addrinfo			*result = NULL;
		struct addrinfo			*addr;

		rc = getaddrinfo(mapping->node, mapping->service, &hints, &result);
		if (rc) {
			fprintf(stderr, "getaddrinfo(%s,%s): %s\n",
				mapping->node, mapping->service, gai_strerror(rc));
			result = NULL;
		}

		for (addr = result; addr != NULL; addr = addr->ai_next) {
			server_sock = socket(addr->ai_family, addr->ai_socktype,
					     addr->ai_protocol);

			if (server_sock == -1)
				continue;

			if (connect(server_sock, addr->ai_addr, addr->ai_addrlen) == 0)
				break;

			close(server_sock);
			server_sock = -1;
		}

		freeaddrinfo(result);
	}

	memset(&resp, 0, sizeof resp);

	if (server_sock != -1) {
		struct p0f_rpc_query	q = {
			.addr_family	=  p0f_addr_to_sa_family(query.addr_type),
		};

		static_assert(sizeof q.src_addr == sizeof query.addr,
			      "types of src_addr and addr_peer differ");
		memcpy(q.src_addr, query.addr, sizeof query.addr);

#if 0
		static_assert(sizeof q.dst_addr == sizeof addr_host,
			      "types of dst_addr and addr_host differ");
		memcpy(q.dst_addr, addr_host, sizeof addr_host);
#endif


		if (send_all(server_sock, &q, sizeof q) != 0)
			resp_len = -1;
		else
			resp_len = receive_response(server_sock, &resp);

		close(server_sock);
	}

	if (resp_len == -1)
		goto err;

	if (send_all(s, &resp, resp_len) != 0)
		goto err;

	close(s);
	_exit(0);

err:
	close(s);
	_exit(1);
}

static void run(struct cmdline_options const *opts, int p0f_sock)
{
	unsigned int		num_childs = 0;
	sigset_t		block_set;

	sigemptyset(&block_set);
	sigaddset(&block_set, SIGCHLD);

	for (;;) {
		int		s;
		pid_t		pid;

		if (num_childs >= opts->max_queries) {
			if (waitpid(0, NULL, 0) > 0)
				--num_childs;
		}

		if (num_childs >= opts->max_queries)
			continue;

		while (waitpid(0, NULL, WNOHANG) > 0)
			--num_childs;

		sigprocmask(SIG_UNBLOCK, &block_set, NULL);
		s = accept(p0f_sock, NULL, NULL);
		sigprocmask(SIG_BLOCK, &block_set, NULL);

		if (s < 0 && errno == EINTR) {
			continue;
		} else if (s < 0) {
			perror("accept()");
			break;
		}

		pid = fork();
		if (pid == -1) {
			perror("fork()");
			break;
		} else if (pid == 0) {
			close(p0f_sock);
			handle_query(opts, s);
			_exit(1);
		} else {
			close(s);
			++num_childs;
		}
	}
}

static void warm_up(struct cmdline_options const *opts)
{
	size_t				i;
	struct addrinfo const		hints = {
		.ai_family	=  (opts->prefer_ip4 ? AF_INET :
				    opts->prefer_ip6 ? AF_INET6 :
				    AF_UNSPEC),
		.ai_socktype	=  SOCK_STREAM,
		.ai_flags	=  0,
		.ai_protocol	=  0,
	};

	for (i = 0; i < opts->num_mappings; ++i) {
		struct addrinfo		*result = NULL;
		int			rc;

		rc = getaddrinfo(opts->mappings[i].node,
				 opts->mappings[i].service,
				 &hints, &result);

		if (rc >= 0)
			freeaddrinfo(result);
	}
}

int main(int argc, char *argv[])
{
	struct cmdline_options	opts = {
		.daemon = {
			.user	= DISPATCHER_USER,
			.mode	= MODE_FOREGROUND
		},
		.socket_file	= DISPATCHER_SOCKFILE,
		.max_queries	= 100,
	};
	int			p0f_sock = -1;

	while (1) {
		int		c = getopt_long(argc, argv, "+u:m:s:46", CMDLINE_OPTIONS, 0);
		if (c==-1) break;

		switch (c) {
		case CMD_HELP:		show_help();
		case CMD_VERSION:	show_version();

		case CMD_PIDFILE:	opts.daemon.pidfile = optarg; break;
		case CMD_CHROOT:	opts.daemon.chroot  = optarg; break;
		case CMD_DAEMON:	opts.daemon.mode = MODE_BACKGROUND; break;
		case CMD_SIGSTOP:	opts.daemon.mode = MODE_SIGSTOP;    break;
		case 'u':		opts.daemon.user = optarg; break;
		case '4':		opts.prefer_ip4  = 1; break;
		case '6':		opts.prefer_ip6  = 1; break;
		case 's':		opts.socket_file = optarg; break;
		case CMD_STRICT:	opts.strict_mode = true; break;
		case 'm':
			if (add_mapping(&opts, optarg) < 0)
				goto err;
			break;
		default:
			fputs("Try '--help' for more information.\n", stderr);
			goto err;
		}
	}

	unlink(opts.socket_file);	/* ignore errors */

	p0f_sock = open_p0f_socket(&opts);
	if (p0f_sock < 0)
		goto err;

	if (ensc_daemonize(&opts.daemon) < 0)
		goto err;

	if (set_sighandlers() < 0)
		goto err;

	warm_up(&opts);
	run(&opts, p0f_sock);

err:
	if (p0f_sock != -1) {
		unlink(opts.socket_file);
		close(p0f_sock);
	}

	free(opts.mappings);
	return EXIT_FAILURE;
}

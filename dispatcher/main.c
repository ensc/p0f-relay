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

#include <getopt.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <p0f-relay/p0f-query.h>
#include <p0f-relay/rpc.h>
#include <common/daemonize.h>
#include <common/io.h>

#ifndef DISPATCHER_SOCKFILE
#  define DISPATCHER_SOCKFILE	LOCALSTATEDIR "/run/p0frun/sock"
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
	struct in_addr			dst_addr;
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
	{ "chroot",      no_argument,       NULL, CMD_CHROOT },
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

	if (inet_pton(AF_INET, from, &m.dst_addr) < 0) {
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

	printf("mapping[%zu] = %s / %s / %s (%s, %s)\n", opts->num_mappings,
	       inet_ntoa(m.dst_addr), m.node, m.service, from, port);

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

static struct p0f_mapping const *find_mapping(struct cmdline_options const *opts,
					      struct p0f_query const *q)
{
	size_t		i;

	for (i = 0; i < opts->num_mappings; ++i) {
		struct in_addr			q_addr = { q->dst_ad };

		printf("  %zu: %s", i, inet_ntoa(q_addr));
		printf(" vs %s\n", inet_ntoa(opts->mappings[i].dst_addr));


		if (memcmp(&q_addr, &opts->mappings[i].dst_addr, sizeof q_addr) == 0)
			return &opts->mappings[i];
	}

	return NULL;
}

union response_local {
	struct p0f_response	r;
	struct p0f_status	s;
} __packed;

static ssize_t receive_response(int s, union response_local *dst,
				unsigned int query_id)
{
	union {
		be32_t				type;
		struct p0f_rpc_response		r;
		struct p0f_rpc_status		s;
	} __packed				msg;
	be32_t					len;
	ssize_t					dst_len;

	if (recv_all(s, &len, sizeof len) != 0 ||
	    recv_all(s, &msg, be32toh(len)) != 0)
		return -1;

	switch (be32toh(msg.type)) {
	case P0F_RPC_MSG_RESPONSE:
		dst_len       = sizeof dst->r;

		dst->r.magic  = QUERY_MAGIC;
		dst->r.id     = query_id;
		dst->r.type   = msg.r.result;
		dst->r.fw     = msg.r.fw;
		dst->r.nat    = msg.r.nat;
		dst->r.real   = msg.r.real;

		dst->r.dist   = msg.r.dist;
		dst->r.score  = be16toh(msg.r.score);
		dst->r.mflags = be16toh(msg.r.mflags);
		dst->r.uptime = be32toh(msg.r.uptime);

		memcpy(dst->r.genre,  msg.r.genre,  sizeof dst->r.genre);
		memcpy(dst->r.detail, msg.r.detail, sizeof dst->r.detail);
		memcpy(dst->r.link,   msg.r.link,   sizeof dst->r.link);
		memcpy(dst->r.tos,    msg.r.tos,    sizeof dst->r.tos);

		break;

	case P0F_RPC_MSG_STATUS:
		dst_len          = sizeof dst->s;

		dst->s.magic     = QUERY_MAGIC;
		dst->s.id        = query_id;
		dst->s.type      = RESP_STATUS;

		dst->s.mode      = msg.s.mode;
		dst->s.fp_cksum  = be32toh(msg.s.fp_cksum);
		dst->s.cache     = be32toh(msg.s.cache);
		dst->s.packets   = be32toh(msg.s.packets);
		dst->s.matched   = be32toh(msg.s.matched);
		dst->s.queries   = be32toh(msg.s.queries);
		dst->s.cmisses   = be32toh(msg.s.cmisses);
		dst->s.uptime    = be32toh(msg.s.uptime);

		memcpy(dst->s.version,  msg.s.version,  sizeof dst->s.version);
		break;

	default:
		return -1;
	}

	return dst_len;
}

static size_t fill_error_fp(struct p0f_response	*r, unsigned int id,
			    unsigned int code)
{
	r->magic = QUERY_MAGIC;
	r->id    = id;
	r->type  = code;

	return sizeof *r;
}

static void handle_query(struct cmdline_options const *opts, int s)
{
	struct p0f_query		query;
	struct p0f_mapping const	*mapping;
	int				server_sock = -1;
	union response_local		resp;
	ssize_t				resp_len = -1;

	if (recv_all(s, &query, sizeof query) != 0)
		goto err;

	if (query.magic != QUERY_MAGIC)
		goto err;

	{
		char	buf[128];
		size_t	l;

		l = sprintf(buf, "%s:%u -> ",
			    inet_ntoa(*(struct in_addr *)&query.src_ad),
			    ntohs(query.src_port));

		sprintf(buf + l, "%s:%u",
			inet_ntoa(*(struct in_addr *)&query.dst_ad),
			ntohs(query.dst_port));
		printf("query: %s\n", buf);
	}

	mapping = find_mapping(opts, &query);
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
		struct p0f_rpc_query const	q = {
			.src_addr	=  query.src_ad,
			.dst_addr	=  query.dst_ad,
			.src_port	=  query.src_port,
			.dst_port	=  query.dst_port,
			.type		=  query.type,
		};

		if (send_all(server_sock, &q, sizeof q) != 0)
			resp_len = -1;
		else
			resp_len = receive_response(server_sock, &resp, query.id);

		close(server_sock);
	}

	if (resp_len == -1) {
		switch (query.type) {
		case QTYPE_FINGERPRINT:
			resp_len = fill_error_fp(&resp.r, query.id, RESP_NOMATCH);
			break;

		case QTYPE_STATUS:
		default:
			resp_len = 0;
			break;
		}
	}

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

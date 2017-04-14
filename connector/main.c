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

#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <p0f-relay/rpc.h>
#include <p0f-relay/api.h>
#include <common/daemonize.h>
#include <common/io.h>

#include <common/compat.h>

#ifndef P0F_SOCKFILE
#  define P0F_SOCKFILE	LOCALSTATEDIR "/run/p0frun/sock"
#endif

#ifndef P0F_USER
#  define P0F_USER	"p0f-connector"
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
};

struct cmdline_options {
	struct daemonize_options	daemon;

	char const			*p0f_socket;
	char const			*listen_node;
	char const			*listen_service;
	unsigned int			max_queries;

	unsigned int			prefer_ip4:1;
	unsigned int			prefer_ip6:1;
};

static struct option const CMDLINE_OPTIONS[] = {
	{ "help",        no_argument,       NULL, CMD_HELP },
	{ "version",     no_argument,       NULL, CMD_VERSION },
	{ "daemon",      no_argument,       NULL, CMD_DAEMON },
	{ "sigstop",     no_argument,       NULL, CMD_SIGSTOP },
	{ "pidfile",     required_argument, NULL, CMD_PIDFILE },
	{ "user",        required_argument, NULL, 'u' },
	{ "listen",      required_argument, NULL, 'l' },
	{ NULL,          no_argument,       NULL, '4' },
	{ NULL,          no_argument,       NULL, '6' },
	{ NULL, 0, NULL, 0}
};

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

static int parse_listen(char const **node, char const **service,
			char const *arg)
{
	char		*tmp = strdupa(arg);
	char		*del = strchr(tmp, '@');
	char const	*node_ptr;
	char const	*service_ptr = tmp;

	free((void*)*node);
	free((void*)*service);

	if (del) {
		*del = '\0';
		node_ptr = del + 1;
	} else
		node_ptr = NULL;

	if (node_ptr == NULL || *node_ptr == '\0')
		*node = NULL;
	else
		*node = strdup(node_ptr);

	if (service_ptr == NULL || *service_ptr == '\0')
		*service = NULL;
	else
		*service = strdup(service_ptr);

	return 0;
}

static int open_listen_sock(struct cmdline_options const *opts)
{
	struct addrinfo const		hints = {
		.ai_family	=  (opts->prefer_ip4 ? AF_INET :
				    opts->prefer_ip6 ? AF_INET6 :
				    AF_UNSPEC),
		.ai_socktype	=  SOCK_STREAM,
		.ai_flags	=  AI_PASSIVE,
		.ai_protocol	=  0,
	};
	struct addrinfo	*result = NULL;
	struct addrinfo	*addr;
	int		rc;
	char const	*service = (opts->listen_service ? opts->listen_service :
				    DEFAULT_PORT);
	int		server_sock = -1;
	int		last_errno = 0;

	rc = getaddrinfo(opts->listen_node, service, &hints, &result);

	if (rc) {
		fprintf(stderr, "getaddrinfo(%s,%s): %s\n",
			opts->listen_node, service, gai_strerror(rc));
		result = NULL;
	}

	for (addr = result; addr != NULL; addr = addr->ai_next) {
		int const	ONE = 1;

		server_sock = socket(addr->ai_family, addr->ai_socktype,
				     addr->ai_protocol);
		last_errno = errno;

		if (server_sock == -1)
			continue;

		setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof ONE);

		if (bind(server_sock, addr->ai_addr, addr->ai_addrlen) == 0)
			break;
		last_errno = errno;

		close(server_sock);
		server_sock = -1;
	}

	if (server_sock == -1 && result != NULL) {
		fprintf(stderr, "could not bind to specified address: %s\n",
			strerror(last_errno));
		rc = -1;
	}

	freeaddrinfo(result);

	if (server_sock != -1) {
		rc = listen(server_sock, 25);
		if (rc < 0)
			perror("listen()");

	}

	if (rc < 0 && server_sock != -1) {
		close(server_sock);
		server_sock = -1;
	}

	return server_sock;
}

static uint32_t	query_id;

#define _copy_fields(a, b, field) do { \
		static_assert(sizeof (a)->field == sizeof (b)->field, \
			      "differently sized attributes"); \
		memcpy((a)->field, (b)->field, sizeof (a)->field); \
	} while(0)

static int send_response(int s, struct p0f_api_response const *resp)
{
	struct p0f_rpc_response		rpc = {
		.status		= htobe32(resp->status),
		.first_seen	= htobe32(resp->first_seen),
		.last_seen	= htobe32(resp->last_seen),
		.total_conn	= htobe32(resp->total_conn),
		.uptime_min	= htobe32(resp->uptime_min),
		.up_mod_days	= htobe32(resp->up_mod_days),
		.last_nat	= htobe32(resp->last_nat),
		.last_chg	= htobe32(resp->last_chg),
		.distance	= htobe16(resp->distance),
		.bad_sw		= resp->bad_sw,
		.os_match_q	= resp->os_match_q,
	};
	be32_t const			len = htobe32(sizeof rpc);

	_copy_fields(&rpc, resp, os_name);
	_copy_fields(&rpc, resp, os_flavor);
	_copy_fields(&rpc, resp, http_name);
	_copy_fields(&rpc, resp, http_flavor);
	_copy_fields(&rpc, resp, link_type);
	_copy_fields(&rpc, resp, language);

	if (send_all(s, &len, sizeof len) != 0 ||
	    send_all(s, &rpc, sizeof rpc) != 0)
		return -1;

	return 0;
}

static sa_family_t sa_family_to_p0f_addr(u8 af_family)
{
	switch (af_family) {
	case AF_INET:
		return P0F_ADDR_IPV4;
	case AF_INET6:
		return P0F_ADDR_IPV6;
	default:
		return 0;
	}
}

static void handle_query(struct cmdline_options const *opts, int s,
			 struct sockaddr_un const *p0f_addr)
{
	int			p0f_fd = -1;
	struct p0f_rpc_query	q;

	(void)opts;

	p0f_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (p0f_fd < 0) {
		perror("socket()");
		goto err;
	}

	if (connect(p0f_fd, (void const *)p0f_addr, sizeof *p0f_addr) < 0) {
		perror("connect()");
		goto err;
	}

	if (recv_all(s, &q, sizeof q) != 0)
		goto err;

	shutdown(s, SHUT_RD);

	{
		struct p0f_api_query	p0f_query = {
			.magic		= P0F_QUERY_MAGIC,
			.addr_type	= sa_family_to_p0f_addr(q.addr_family),
		};

		memcpy(p0f_query.addr, q.src_addr, sizeof p0f_query.addr);

		if (send_all(p0f_fd, &p0f_query, sizeof p0f_query) != 0)
			goto err;

		shutdown(p0f_fd, SHUT_WR);
	}

	{
		struct p0f_api_response	resp;

		if (recv_all(p0f_fd, &resp, sizeof resp) != 0)
			goto err;

		shutdown(p0f_fd, SHUT_RD);

		if (send_response(s, &resp) < 0)
			goto err;
	}

	close(p0f_fd);
	close(s);

	_exit(0);

err:
	if (p0f_fd != -1)
		close(p0f_fd);

	close(s);
	_exit(1);
}

static void run(struct cmdline_options const *opts, int disp_sock)
{
	unsigned int		num_childs = 0;
	sigset_t		block_set;
	struct sockaddr_un	p0f_addr = {
		.sun_family	=  AF_UNIX
	};

	sigemptyset(&block_set);
	sigaddset(&block_set, SIGCHLD);


	strncpy(p0f_addr.sun_path, opts->p0f_socket,
		sizeof p0f_addr.sun_path - 1);

	(void)opts;
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
		s = accept(disp_sock, NULL, NULL);
		sigprocmask(SIG_BLOCK, &block_set, NULL);

		if (s < 0 && errno == EINTR) {
			continue;
		} else if (s < 0) {
			perror("accept()");
			break;
		}

		++query_id;
		pid = fork();

		if (pid == -1) {
			perror("fork()");
			break;
		} else if (pid == 0) {
			close(disp_sock);
			handle_query(opts, s, &p0f_addr);
			_exit(1);
		} else {
			close(s);
			++num_childs;
		}
	}
}

static void show_help(void)
{
	puts("Usage: p0f-connector [--pidfile <filename>] [--daemon|--sigstop]\n"
	     "  [--user|-u <username>] [--socket|-s <socket>]\n"
	     "  [-4|-6] [--listen|-l <port>[@<server>]]\n");
	exit(0);
}

static void show_version(void)
{
	puts("p0f-connector " VERSION " -- p0f connector service\n\n"
	     "Copyright (C) 2011 Enrico Scholz\n"
	     "This program is free software; you may redistribute it under the terms of\n"
	     "the GNU General Public License.  This program has absolutely no warranty.");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct cmdline_options	opts = {
		.daemon = {
			.user	= P0F_USER,
			.mode	= MODE_FOREGROUND
		},
		.p0f_socket	= P0F_SOCKFILE,
		.max_queries	= 100,
	};
	int			listen_sock = -1;

	while (1) {
		int		c = getopt_long(argc, argv, "+u:s:l:46", CMDLINE_OPTIONS, 0);
		if (c==-1) break;

		switch (c) {
		case CMD_HELP:		show_help();
		case CMD_VERSION:	show_version();

		case CMD_PIDFILE:	opts.daemon.pidfile = optarg; break;
		case CMD_DAEMON:	opts.daemon.mode    = MODE_BACKGROUND; break;
		case CMD_SIGSTOP:	opts.daemon.mode    = MODE_SIGSTOP;    break;
		case 'u':		opts.daemon.user    = optarg; break;
		case '4':		opts.prefer_ip4     = 1; break;
		case '6':		opts.prefer_ip6     = 1; break;
		case 's':		opts.p0f_socket     = optarg; break;
		case 'l':
			if (parse_listen(&opts.listen_node,
					 &opts.listen_service, optarg) < 0)
				goto err;
			break;


		default:
			fputs("Try '--help' for more information.\n", stderr);
			goto err;
		}
	}

	if (opts.prefer_ip4 && opts.prefer_ip6) {
		fputs("both '-4' and '-6' specified\n", stderr);
		goto err;
	}

	listen_sock = open_listen_sock(&opts);
	if (listen_sock < 0)
		goto err;

	if (set_sighandlers() < 0)
		goto err;

	if (ensc_daemonize(&opts.daemon) < 0)
		goto err;

	run(&opts, listen_sock);

err:
	if (listen_sock != -1)
		close(listen_sock);

	free((void *)opts.listen_node);
	free((void *)opts.listen_service);

	return EXIT_FAILURE;
}

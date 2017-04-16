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

#include "common/daemonize.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/wait.h>

struct daemonize_state {
	struct daemonize_options const	*opts;
};

static int drop_privilegies(struct daemonize_options const *opts)
{
	struct passwd	*pw = getpwnam(opts->user);

	if (pw == NULL) {
		perror("getpwnam()");
		return -1;
	}

	if (initgroups(opts->user, pw->pw_gid) < 0) {
		perror("initgroups()");
		return -1;
	}

	endpwent();

	if (opts->chroot) {
		if (chroot(opts->chroot) < 0) {
			perror("chroot()");
			return -1;
		}
	}

	if (chdir("/") < 0) {
		perror("chdir(/)");
		return -1;
	}

	if (setgid(pw->pw_gid) < 0) {
		perror("setgid()");
		return -1;
	}

	if (setuid(pw->pw_uid) < 0) {
		perror("setuid()");
		return -1;
	}

	return 0;
}

static void write_pid(int pid_fd, pid_t pid)
{
	if (pid_fd != -1) {
		dprintf(pid_fd, "%u\n", (unsigned int)pid);
		close(pid_fd);
	}
}

static int daemonize(struct daemonize_options const *opts,
		     int fd_null[2], int pid_fd)
{
	if (opts->mode != MODE_BACKGROUND)
		write_pid(pid_fd, getpid());
	else {
		pid_t		pid = 0;
		int		st;

		pid = fork();

		switch (pid) {
		case -1:
			perror("fork()");
			return -1;

		case 0:
			if (setsid() < 0) {
				perror("setsid()");
				_exit(1);
			}

			if (dup2(fd_null[0], 0) < 0 ||
			    dup2(fd_null[1], 1) < 0 ||
			    dup2(fd_null[1], 2) < 0) {
				perror("open(\"/dev/null\"");
				_exit(1);
			}

			close(fd_null[0]);
			close(fd_null[1]);

			pid = fork();
			switch (pid) {
			case -1:
				_exit(1);

			case 0:
				if (pid_fd >= 0)
					close(pid_fd);
				break;

			default:
				write_pid(pid_fd, pid);
				_exit(0);
			}

			break;

		default:
			if (pid_fd >= 0)
				close(pid_fd);
			close(fd_null[0]);
			close(fd_null[1]);

			fd_null[0] = -1;
			fd_null[1] = -1;

			if (waitpid(pid, &st, 0) < 0) {
				perror("waitpid()");
				_exit(1);
			}

			if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
				fputs("child exited abnormally", stderr);
				_exit(1);
			}

			_exit(0);
			break;
		}
	}

	switch (opts->mode) {
	case MODE_BACKGROUND:
	case MODE_FOREGROUND:
		break;

	case MODE_SIGSTOP:
		raise(SIGSTOP);
		break;
	}

	return 0;
}

int ensc_daemonize(struct daemonize_options const *opts)
{
	int				pid_fd = -1;
	int				fd_null[2] = { -1, -1 };

	if (opts->pidfile) {
		unlink(opts->pidfile);	/* ignore errors */
		pid_fd = open(opts->pidfile,
			      O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (pid_fd < 0) {
			perror("open(<pidfile>)");
			goto err;
		}
	};

	if (opts->mode == MODE_BACKGROUND) {
		/* open /dev/null before we go into the chroot */
		fd_null[0] = open("/dev/null", O_RDONLY | O_NOCTTY);
		fd_null[1] = open("/dev/null", O_WRONLY | O_NOCTTY);

		if (fd_null[0] == -1 || fd_null[1] == -1) {
			perror("open(\"/dev/null\"");
			goto err;
		}
	}

	if (opts->user[0] != '\0' && drop_privilegies(opts) < 0)
		goto err;

	/* we did not called drop_privilegies() which goes into '/' */
	if (opts->user[0] == '\0' && chdir("/") < 0) {
		perror("chdir(\"/\")");
		goto err;
	}

	if (daemonize(opts, fd_null, pid_fd) < 0)
		goto err;

	/* daemonize() closes 'pid_fd' */

	return 0;

err:
	if (fd_null[1] != -1)
		close(fd_null[1]);

	if (fd_null[0] != -1)
		close(fd_null[0]);

	if (pid_fd != -1)
		close(pid_fd);

	return -1;
}

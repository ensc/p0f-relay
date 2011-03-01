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

#ifndef H_ENSC_P0F_RELAY_COMMON_IO_H
#define H_ENSC_P0F_RELAY_COMMON_IO_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

static int recv_all(int s, void *buf, size_t len)
{
	while (len > 0) {
		ssize_t		l = recv(s, buf, len, 0);

		if (l > 0) {
			buf += l;
			len -= l;
		} else if (l == 0) {
			break;
		} else if (errno == EINTR)
			continue;
		else {
			perror("recv()");
			return -1;
		}
	}

	return len;
}

static int send_all(int s, void const *buf, size_t len)
{
	while (len > 0) {
		ssize_t		l = send(s, buf, len, MSG_NOSIGNAL);

		if (l > 0) {
			buf += l;
			len -= l;
		} else if (l == 0) {
			break;
		} else if (errno == EINTR)
			continue;
		else {
			perror("send()");
			return -1;
		}
	}

	return len;
}

#endif	/* H_ENSC_P0F_RELAY_COMMON_IO_H */

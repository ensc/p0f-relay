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

#ifndef H_ENSC_COMMON_DAEMONIZE_H
#define H_ENSC_COMMON_DAEMONIZE_H

struct daemonize_options {
	char const		*user;
	char const		*pidfile;
	char const		*chroot;

	enum { MODE_FOREGROUND, MODE_BACKGROUND,
	       MODE_SIGSTOP }	mode;
};

int ensc_daemonize(struct daemonize_options const *);

#endif	/* H_ENSC_COMMON_DAEMONIZE_H */

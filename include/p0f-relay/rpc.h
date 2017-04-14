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

#ifndef H_ENSC_P0F_RELAY_RPC_H
#define H_ENSC_P0F_RELAY_RPC_H

#include <stdint.h>

#define __packed	__attribute__((__packed__))

typedef uint32_t	be32_t;
typedef uint16_t	be16_t;
typedef uint8_t		be8_t;

#if defined(__GLIBC_PREREQ) && __GLIBC_PREREQ(2,9)
#  include <endian.h>
#else
#  include <arpa/inet.h>
#  define htobe32	htonl
#  define htobe16	htons
#  define be32toh	htonl
#  define be16toh	htons
#endif

struct p0f_rpc_query {
	be32_t		addr_family;
	be8_t		src_addr[16];
//	be8_t		dst_addr[16];
} __packed;

struct p0f_rpc_response {
	be32_t		type;		/* unused atm */
	
	be32_t		status;
	be32_t		first_seen;
	be32_t		last_seen;
	be32_t		total_conn;

	be32_t		uptime_min;
	be32_t		up_mod_days;

	be32_t		last_nat;
	be32_t		last_chg;

	be16_t		distance;

	be8_t		bad_sw;
	be8_t		os_match_q;

	unsigned char	os_name[32];
	unsigned char	os_flavor[32];

	unsigned char	http_name[32];
	unsigned char	http_flavor[32];

	unsigned char	link_type[32];
	unsigned char	language[32];
} __packed;

#endif	/* H_ENSC_P0F_RELAY_RPC_H */

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

struct p0f_rpc_query {
	be32_t		src_addr;
	be32_t		dst_addr;
	be16_t		src_port;
	be16_t		dst_port;
	be8_t		type;
} __packed;

#define P0F_RPC_MSG_QUERY	0
#define P0F_RPC_MSG_RESPONSE	1
#define P0F_RPC_MSG_STATUS	2

struct p0f_rpc_response {
	be32_t		type;
	be32_t		uptime;
	be16_t		score;
	be16_t		mflags;
	be8_t		detail[40];
	be8_t		genre[20];
	be8_t		link[30];
	be8_t		tos[30];
	be8_t		fw;
	be8_t		nat;
	be8_t		real;
	be8_t		result;
	be8_t		dist;
} __packed;

struct p0f_rpc_status {
	be32_t		type;
	be32_t		fp_cksum;
	be32_t		cache;
	be32_t		packets;
	be32_t		matched;
	be32_t		queries;
	be32_t		cmisses;
	be32_t		uptime;
	be8_t		mode;
	be8_t		version[16];
} __packed;



#endif	/* H_ENSC_P0F_RELAY_RPC_H */

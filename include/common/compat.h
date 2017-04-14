/*	--*- c -*--
 * Copyright (C) 2017 Enrico Scholz <enrico.scholz@ensc.de>
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

#ifndef H_ENSC_P0F_RELAY_COMMON_COMPAT_H
#define H_ENSC_P0F_RELAY_COMMON_COMPAT_H

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ < 201112L)
#  define static_assert(a,b) do { } while (0)
#endif

#endif	/* H_ENSC_P0F_RELAY_COMMON_COMPAT_H */

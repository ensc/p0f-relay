# Copyright (C) 2011 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

GIT ?= git
TAR ?= tar

BUILD_CC ?= $(CC)
BUILD_CPPFLAGS ?= $(CPPFLAGS)
BUILD_CFLAGS ?= $(CFLAGS)
BUILD_LDFLAGS ?= $(LDFLAGS)

AM_BUILD_CPPFLAGS ?= $(AM_CPPFLAGS)
AM_BUILD_CFLAGS ?= $(AM_CFLAGS)
AM_BUILD_LDFLAGS ?= $(AM_LDFLAGS)

INSTALL ?= install
INSTALL_EXEC ?= $(INSTALL) -p -m 0755
INSTALL_DATA ?= $(INSTALL) -p -m 0644

prefix ?= /usr/local
bindir ?= $(prefix)/bin
sbindir ?= $(prefix)/sbin
libdir ?= $(prefix)/libdir
localstatedir ?= $(prefix)/var

define COMPILE_C
DIST_FILES +=	$${$(1)_SOURCES}

$$(O)$(1):	$${$(1)_SOURCES} $$($(1)_LIBS)
		@mkdir -p $$(dir $$@)
		$${CC} \
$${AM_CPPFLAGS} $${$(1)_CPPFLAGS} $${CPPFLAGS} \
$${AM_CFLAGS} $${$(1)_CFLAGS} $${CFLAGS} \
$${AM_LDFLAGS} $${$(1)_LDFLAGS} $${LDFLAGS} \
$$(filter %.c %.S,$$^) $$($(1)_LIBS) $$(patsubst %,$$(_LDMAP_WL)%,$$(filter %.ld,$$^)) -o $$@
endef

define HOSTCOMPILE_C
DIST_FILES +=	$${$(1)_SOURCES}

$$(O)$(1):	$${$(1)_SOURCES} $$($(1)_LIBS)
		@mkdir -p $$(dir $$@)
		$${BUILD_CC} \
$${AM_BUILD_CPPFLAGS} $${$(1)_CPPFLAGS} $${BUILD_CPPFLAGS} \
$${AM_BUILD_CFLAGS} $${$(1)_CFLAGS} $${BUILD_CFLAGS} \
$${AM_BUILD_LDFLAGS} $${$(1)_LDFLAGS} $${BUILD_LDFLAGS} \
$$(filter %.c %.S,$$^) $$($(1)_LIBS) $$(patsubst %,$$(_LDMAP_WL)%,$$(filter %.ld,$$^)) \
-o $$@
endef

define COMPILE_C_LIBOBJ
$(2).o:		$(2).c $$($(2)_DEPS)
		@mkdir -p $$(dir $$@)
		$${CC} -MD -MF $${@D}/.$${@F}.dep $${AM_CPPFLAGS} $${$(1)_CPPFLAGS} $${CPPFLAGS} $${AM_CFLAGS} $${$(1)_CFLAGS} $${CFLAGS} $$^ -c -o $$@

-include $$(dir $(2))/.$$(notdir $(2).o).dep
endef

define COMPILE_C_LIB
DIST_FILES +=	$${$(1)_SOURCES}

$$(O)$(1).a:	$$(patsubst %.c,%.o,$${filter %.c,$${$(1)_SOURCES}})
		@mkdir -p $$(dir $$@)
		ar cru $$@ $$^

$$(foreach obj,$$(patsubst %.c,%,$${filter %.c,$${$(1)_SOURCES}}),$$(eval $$(call COMPILE_C_LIBOBJ,$(1),$$(obj))))
endef

define _INSTALL_EXEC
install-exec:	$$(DESTDIR)$(2)/$$(notdir $(1))

$$(DESTDIR)$(2)/$$(notdir $(1)):	$$(O)$(1)
		$(INSTALL_EXEC) -D $$< $$@
endef

_host_programs :=	$(bin_PROGRAMS) $(sbin_PROGRAMS) ${noinst_HOST_PROGRAMS}
_target_programs :=	$(noinst_PROGRAMS)
_target_libraries :=	$(noinst_LIBRARIES)

_noinst_stuff :=	${noinst_HOST_PROGRAMS} $(noinst_PROGRAMS) \
			$(addsuffix .a,$(noinst_LIBRARIES)) ${noinst_DATA}

_host_gen :=		${_host_programs} ${pkgdata_DATA}
_target_gen :=		${_target_programs} ${addsuffix .a,${_target_libraries}}

_host_all :=		${_host_gen}
_target_all :=		${_target_gen}

_all_gen :=		${_host_gen} ${_target_gen}
_all_progs :=		${_host_all} ${_target_all}

$(foreach prog,${_target_programs},$(eval $(call COMPILE_C,$(prog))))
$(foreach prog,${_target_libraries},$(eval $(call COMPILE_C_LIB,$(prog))))
$(foreach prog,${_host_programs},$(eval $(call HOSTCOMPILE_C,$(prog))))

$(foreach prog,${bin_PROGRAMS},$(eval $(call _INSTALL_EXEC,$(prog),$$(bindir))))
$(foreach prog,${sbin_PROGRAMS},$(eval $(call _INSTALL_EXEC,$(prog),$$(sbindir))))

_all:		$(addprefix $(O),${_all_gen})

_install:	install-exec

_clean:
		rm -f $(CLEANFILES)
		rm -f $(addprefix $(O),${_all_gen} ${_noinst_stuff})
		rm -f $(addprefix $(O),*.o */*.o *.a */*.a)
		rm -f $(addprefix $(O),.*.dep */.*.dep)
		-rmdir $(O)

_git_rev = $(shell $(GIT) rev-parse --verify --short HEAD)
_git_ver = $(shell $(GIT) rev-list $(_git_rev) | wc -l)

dist-git:
		$(MAKE) .dist DIST_MODE=git pkg_prefix='$(NAME)-g$(_git_ver)+$(_git_rev)' GIT_REV='${_git_rev}'

ifeq ($(DIST_MODE),git)
.dist:		$(pkg_prefix).tar

$(pkg_prefix).tar:	.$(pkg_prefix).tar
		rm -f $@
		$(TAR) rf $< --transform='s!^$(O)!!' $(EXTRA_DIST) --owner root --group root --mode u+w,g-w,a+rX --mtime=now
		mv $< $@

.$(pkg_prefix).tar:
		rm -f $@
		$(GIT) archive --format=tar --prefix='${pkg_prefix}/' '${GIT_REV}' -o $@
endif

.PHONY:		_clean_common _all _install install-exec

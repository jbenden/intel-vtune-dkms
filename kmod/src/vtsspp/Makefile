###############################################################################
# -*- Mode: makefile -*-
#
# Copyright (C) 2010-2019 Intel Corporation.  All Rights Reserved.
#
# This file is part of SEP Development Kit
#
# SEP Development Kit is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# SEP Development Kit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SEP Development Kit; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#
# As a special exception, you may use this file as part of a free software
# library without restriction.  Specifically, if other files instantiate
# templates or use macros or inline functions from this file, or you compile
# this file and link it with other files to produce an executable, this
# file does not by itself cause the resulting executable to be covered by
# the GNU General Public License.  This exception does not however
# invalidate any other reasons why the executable file might be covered by
# the GNU General Public License.
#
###############################################################################

DRIVER_NAME := vtsspp

MARCH ?= $(shell uname -m | sed -e s/i.86/i386/)

# Check for external define from SEP Makefile
ifeq ($(KERNEL_VERSION),)
KVER  ?= $(shell uname -r)
else
KVER  ?= $(KERNEL_VERSION)
endif

# Check for external define from SEP Makefile
ifeq ($(KERNEL_SRC_DIR),)
KDIR  ?= /lib/modules/$(KVER)/build
else
KDIR  ?= $(KERNEL_SRC_DIR)
endif

PWD := $(shell pwd)
INSTALL ?= $(PWD)
PLATFORM := unknown
ifeq ($(MARCH),i386)
PLATFORM := x32
endif
ifeq ($(MARCH),x86_64)
PLATFORM := x32_64
endif

###############################################################################
# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)

obj-m := $(DRIVER_NAME).o
$(DRIVER_NAME)-objs := module.o collector.o procfs.o transport.o record.o \
                       task_map.o globals.o cpuevents.o user_vm.o stack.o \
                       apic.o dsa.o bts.o pebs.o lbr.o nmiwd.o ipt.o uec.o \
                       unwind.o utils.o memory_pool.o
ifeq ($(PLATFORM),x32)
EXTRA_CFLAGS += -DVTSS_ARCH_32
$(DRIVER_NAME)-objs += sys32.o
endif
ifeq ($(PLATFORM),x32_64)
ifneq ($(ARCH),)
DARCH := $(shell echo $(ARCH) | sed -e s/i386/32/ -e s/x86_// -e s/x86/64/ -e s/[lk]1om/KNX/)
EXTRA_CFLAGS += -DVTSS_ARCH_$(DARCH)
$(DRIVER_NAME)-objs += sys$(DARCH).o
else
EXTRA_CFLAGS += -DVTSS_ARCH_64
$(DRIVER_NAME)-objs += sys64.o
endif
endif

EXTRA_CFLAGS  += -Wall
VTSS_FEATURES := $(subst :, ,$(VTSS))
ifneq ($(filter trace, $(VTSS_FEATURES)),)
EXTRA_CFLAGS  += -DVTSS_DEBUG_TRACE
endif
ifneq ($(filter profile, $(VTSS_FEATURES)),)
EXTRA_CFLAGS  += -DVTSS_DEBUG_PROFILE
endif
ifneq ($(filter uec, $(VTSS_FEATURES)),)
EXTRA_CFLAGS += -DVTSS_USE_UEC
endif
ifneq ($(filter syscall, $(VTSS_FEATURES)),)
EXTRA_CFLAGS += -DVTSS_SYSCALL_TRACE
endif
ifneq ($(filter android, $(VTSS_FEATURES)),)
EXTRA_CFLAGS += -DVTSS_CHECK_IP_IN_MAP -DVTSS_STACK_LIMIT=0x10000
endif
EXTRA_CFLAGS += -DVTSS_VMA_SEARCH_BOOST
ifneq ($(filter mic, $(VTSS_FEATURES)),)
EXTRA_CFLAGS += -DVTSS_OVERFLOW_PAUSE -DVTSS_NO_BTS -DVTSS_VMA_SEARCH_BOOST
endif
ifneq ($(filter nmi, $(VTSS_FEATURES)),)
EXTRA_CFLAGS += -DVTSS_USE_NMI
endif

ifeq ($(wildcard $(obj)/vtssrtcfg.h),)
COPY_PUBLIC_HEADERS := $(shell cp $(obj)/../include/* $(obj))
else
COPY_PUBLIC_HEADERS :=
endif 
$(DRIVER_NAME)-objs: COPY_PUBLIC_HEADERS $(obj)/autoconf.h

_KBUILD_CFLAGS := $(call flags,KBUILD_CFLAGS)
CHECK_BUILD    := $(CC) $(KBUILD_CPPFLAGS) $(CPPFLAGS) $(LINUXINCLUDE) \
                  $(_KBUILD_CFLAGS) $(CFLAGS_KERNEL) $(EXTRA_CFLAGS) $(CFLAGS) \
                  -DKBUILD_BASENAME=\"$(DRIVER_NAME)\" -Werror -S -o /dev/null -xc >> $(obj)/.autoconf.log 2>&1

autoconf-srcs := $(sort $(wildcard $(M)/autoconf/*.c))
$(addprefix $(obj)/,$($(DRIVER_NAME)-objs)): $(obj)/autoconf.h
$(obj)/autoconf.h: $(autoconf-srcs) $(M)/Makefile
	@echo "/**" > $@
	@echo " * Automatically generated file; DO NOT EDIT." >> $@
	@echo " * Configuration for $(KERNELRELEASE) kernel" >> $@
	@echo " */" >> $@
	@echo "#ifndef _VTSS_AUTOCONF_H_" >> $@
	@echo "#define _VTSS_AUTOCONF_H_" >> $@
	@echo "" >> $@
	@$(foreach f, $(autoconf-srcs), echo -n "  CHK     $(notdir $(f:.c=))... "; echo CC $(notdir $f) >> $(obj)/.autoconf.log; if $(CHECK_BUILD) $(f); then (echo -n "#define "; echo -n VTSS_AUTOCONF_$(notdir $(f:.c=)) | tr '\-a-z' '\_A-Z'; echo " 1") >> $@; echo yes; else echo no; fi;)
	@echo "" >> $@
	@if [ -f $(obj)/version.h ]; then \
		echo "#include \"version.h\""; \
		echo ""; \
	fi >> $@
	@echo "#endif" >> $@


###############################################################################
# Otherwise, we were called directly from the command line;
# invoke the kernel build system.
else


# eventual filename of the driver
ifneq ($(ARCH),)
ifeq ($(ARCH),x86_64)
DRIVER_FILENAME := $(DRIVER_NAME)-x32_64-$(KVER)smp.ko
else 
DRIVER_FILENAME := $(DRIVER_NAME)-$(ARCH)-$(KVER)smp.ko
endif
else
DRIVER_FILENAME := $(DRIVER_NAME)-$(PLATFORM)-$(KVER)smp.ko
endif

.PHONY: default all clean distclean install

default: all

all:
ifeq ($(PLATFORM),x32)
	@echo " *** Linux 32-bit targets are unsupported."
else
	-@$(MAKE) -C $(KDIR) M=$(PWD) V=0 modules
	-cp -f $(DRIVER_NAME).ko $(DRIVER_FILENAME)
endif

clean:
	-rm -f *.o .*.o.cmd .*.o.d .*.ko.cmd .*.ko.unsigned.cmd *.gcno
	-rm -f Module.symvers Modules.symvers *.mod.c modules.order Module.markers
	-rm -rf .tmp_versions
	-rm -f .cache.mk *.o.ur-safe
	-rm -f autoconf.h .autoconf.log
	-rm -f $(DRIVER_NAME).ko $(DRIVER_NAME).ko.unsigned $(DRIVER_FILENAME)

distclean: clean
	-rm -f $(DRIVER_NAME)*.ko

install:
	-@if [ -f $(DRIVER_NAME).ko ]; then \
		if [ "$(INSTALL)" != "." -a "$(INSTALL)" != "$(PWD)" -a "$(INSTALL)" != "$(PWD)/" ]; then \
			cp -f $(DRIVER_NAME).ko $(INSTALL)/$(DRIVER_FILENAME); \
			cp -f insmod-vtsspp $(INSTALL)/insmod-vtsspp; \
			cp -f rmmod-vtsspp $(INSTALL)/rmmod-vtsspp; \
			echo "Installed $(DRIVER_NAME) driver to $(INSTALL)/$(DRIVER_FILENAME)"; \
		fi; \
	else \
		echo "Error: Driver $(DRIVER_NAME) is not found"; exit 1; \
	fi
endif

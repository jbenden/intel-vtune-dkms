/*
  Copyright (C) 2010-2019 Intel Corporation.  All Rights Reserved.

  This file is part of SEP Development Kit

  SEP Development Kit is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  SEP Development Kit is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with SEP Development Kit; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

  As a special exception, you may use this file as part of a free software
  library without restriction.  Specifically, if other files instantiate
  templates or use macros or inline functions from this file, or you compile
  this file and link it with other files to produce an executable, this
  file does not by itself cause the resulting executable to be covered by
  the GNU General Public License.  This exception does not however
  invalidate any other reasons why the executable file might be covered by
  the GNU General Public License.
*/
#include "config.h"
#include "dsa.h"
#include "globals.h"
#include "utils.h"

#include <linux/percpu.h>
#include <linux/slab.h>
#ifdef VTSS_CONFIG_KPTI
#include <asm/cpu_entry_area.h>
#endif

#define DS_AREA_MSR 0x0600

static DEFINE_PER_CPU_SHARED_ALIGNED(unsigned long long, vtss_dsa_cpu_msr);
static DEFINE_PER_CPU_SHARED_ALIGNED(vtss_dsa_t*, vtss_dsa_per_cpu);

vtss_dsa_t* vtss_dsa_get(int cpu)
{
    return per_cpu(vtss_dsa_per_cpu, cpu);
}

void vtss_dsa_init_cpu(void)
{
    if (hardcfg.family == VTSS_FAM_P6) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        vtss_dsa_t *dsa = __get_cpu_var(vtss_dsa_per_cpu);
#else
        vtss_dsa_t *dsa = *this_cpu_ptr(&vtss_dsa_per_cpu);
#endif
        if (IS_DSA_64ON32) {
            dsa->v32.reserved[0] = dsa->v32.reserved[1] = NULL;
            dsa->v32.reserved[2] = dsa->v32.reserved[3] = NULL;
        } else {
            dsa->v64.reserved[0] = dsa->v64.reserved[1] = NULL;
        }
        wrmsrl(DS_AREA_MSR, (size_t)dsa);
    }
}

#ifdef VTSS_CONFIG_KPTI

static int vtss_dsa_alloc_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = (vtss_dsa_t*)&get_cpu_entry_area(cpu)->cpu_debug_store;
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
}

#elif defined(VTSS_CONFIG_KAISER)

static int vtss_dsa_alloc_buffer(int cpu)
{
    void *buffer;

    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
    buffer = vtss_kaiser_alloc_pages(sizeof(vtss_dsa_t), GFP_KERNEL, cpu);
    if (unlikely(!buffer)) {
        ERROR("Cannot allocate DSA buffer on %d CPU", cpu);
        return VTSS_ERR_NOMEMORY;
    }
    per_cpu(vtss_dsa_per_cpu, cpu) = buffer;
    TRACE("allocated buffer for %d cpu, buffer=%p", cpu, buffer);
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    void *buffer;

    buffer = per_cpu(vtss_dsa_per_cpu, cpu);
    vtss_kaiser_free_pages(buffer, sizeof(vtss_dsa_t));
    TRACE("released buffer for %d cpu, buffer=%p", cpu, buffer);
}

#else

static int vtss_dsa_alloc_buffer(int cpu)
{
    per_cpu(vtss_dsa_per_cpu, cpu) = NULL;
    if ((per_cpu(vtss_dsa_per_cpu, cpu) = (vtss_dsa_t*)kmalloc_node(
            sizeof(vtss_dsa_t), (GFP_KERNEL | __GFP_ZERO), cpu_to_node(cpu))) == NULL)
    {
        ERROR("Cannot allocate DSA buffer on %d CPU", cpu);
        return VTSS_ERR_NOMEMORY;
    }
    return 0;
}

static void vtss_dsa_release_buffer(int cpu)
{
    if (per_cpu(vtss_dsa_per_cpu, cpu) != NULL)
        kfree(per_cpu(vtss_dsa_per_cpu, cpu));
}

#endif

static void vtss_dsa_on_each_cpu_init(void* ctx)
{
    if (hardcfg.family == VTSS_FAM_P6) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        rdmsrl(DS_AREA_MSR, __get_cpu_var(vtss_dsa_cpu_msr));
#else
        rdmsrl(DS_AREA_MSR, *this_cpu_ptr(&vtss_dsa_cpu_msr));
#endif
    }
}

static void vtss_dsa_on_each_cpu_fini(void* ctx)
{
    if (hardcfg.family == VTSS_FAM_P6) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        wrmsrl(DS_AREA_MSR, __get_cpu_var(vtss_dsa_cpu_msr));
#else
        wrmsrl(DS_AREA_MSR, *this_cpu_ptr(&vtss_dsa_cpu_msr));
#endif
    }
}

int vtss_dsa_init(void)
{
    int cpu;

    on_each_cpu(vtss_dsa_on_each_cpu_init, NULL, SMP_CALL_FUNCTION_ARGS);
    for_each_possible_cpu(cpu) {
        if (vtss_dsa_alloc_buffer(cpu)) goto fail;
    }
    return 0;
fail:
    for_each_possible_cpu(cpu) {
        vtss_dsa_release_buffer(cpu);
    }
    return VTSS_ERR_NOMEMORY;
}

void vtss_dsa_fini(void)
{
    int cpu;

    on_each_cpu(vtss_dsa_on_each_cpu_fini, NULL, SMP_CALL_FUNCTION_ARGS);
    for_each_possible_cpu(cpu) {
        vtss_dsa_release_buffer(cpu);
    }
}


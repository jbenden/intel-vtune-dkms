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
#include "globals.h"
#include "utils.h"
#include "apic.h"
#include "time.h"
#include "ipt.h"

#include <linux/utsname.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/// processor control blocks
#ifdef DEFINE_PER_CPU_SHARED_ALIGNED
DEFINE_PER_CPU_SHARED_ALIGNED(vtss_pcb_t, vtss_pcb);
#else
DEFINE_PER_CPU(vtss_pcb_t, vtss_pcb);
#endif

/// trace format information to enable forward compatibility
fmtcfg_t fmtcfg[2];

/// system configuration
vtss_syscfg_t syscfg;

/// hardware configuration
vtss_hardcfg_t hardcfg;

vtss_iptcfg_t iptcfg;

/// profiling configuration
process_cfg_t reqcfg;

/* time source for collection */
int vtss_time_source = 0;

/* time limit for collection */
cycles_t vtss_time_limit = 0ULL;

VTSS_DEFINE_PROFILE_STRUCT();

unsigned long vtss_syscall_rsp_ptr = 0;

static void vtss_fmtcfg_init(void)
{
    /*
     * leaf 1: base
     */
    fmtcfg[0].rank = 0;
    fmtcfg[0].and_mask = UEC_LEAF0 | UEC_LEAF1 | UEC_LEAF2 | UEC_LEAF3;
    fmtcfg[0].cmp_mask = UEC_LEAF1;
    fmtcfg[0].defcount = 0x20;

    fmtcfg[0].defbit[0x00] = 4; /// UECL1_ACTIVITY      0x00000001
    fmtcfg[0].defbit[0x01] = 4; /// UECL1_VRESIDX       0x00000002
    fmtcfg[0].defbit[0x02] = 4; /// UECL1_CPUIDX        0x00000004
    fmtcfg[0].defbit[0x03] = 8; /// UECL1_USRLVLID      0x00000008
    fmtcfg[0].defbit[0x04] = 8; /// UECL1_CPUTSC        0x00000010
    fmtcfg[0].defbit[0x05] = 8; /// UECL1_REALTSC       0x00000020
    fmtcfg[0].defbit[0x06] = 1; /// UECL1_MUXGROUP      0x00000040
    fmtcfg[0].defbit[0x07] = 8; /// UECL1_CPUEVENT      0x00000080
    fmtcfg[0].defbit[0x08] = 8; /// UECL1_CHPSETEV      0x00000100
    fmtcfg[0].defbit[0x09] = 8; /// UECL1_OSEVENT       0x00000200
    fmtcfg[0].defbit[0x0a] = 8; /// UECL1_EXECADDR      0x00000400
    fmtcfg[0].defbit[0x0b] = 8; /// UECL1_REFADDR       0x00000800
    fmtcfg[0].defbit[0x0c] = 8; /// UECL1_EXEPHYSADDR   0x00001000
    fmtcfg[0].defbit[0x0d] = 8; /// UECL1_REFPHYSADDR   0x00002000
    fmtcfg[0].defbit[0x0e] = 4; /// UECL1_TPIDX         0x00004000
    fmtcfg[0].defbit[0x0f] = 8; /// UECL1_TPADDR        0x00008000
    fmtcfg[0].defbit[0x10] = 8; /// UECL1_PWREVENT      0x00010000
    fmtcfg[0].defbit[0x11] = 8; /// UECL1_CPURECTSC     0x00020000
    fmtcfg[0].defbit[0x12] = 8; /// UECL1_REALRECTSC    0x00040000
    fmtcfg[0].defbit[0x13] = 81;    /// UECL1_PADDING       0x00080000
    fmtcfg[0].defbit[0x14] = VTSS_FMTCFG_RESERVED;  /// UECL1_UNKNOWN0      0x00100000
    fmtcfg[0].defbit[0x15] = VTSS_FMTCFG_RESERVED;  /// UECL1_UNKNOWN1      0x00200000
    fmtcfg[0].defbit[0x16] = 82;    /// UECL1_SYSTRACE      0x00400000
    fmtcfg[0].defbit[0x17] = 84;    /// UECL1_LARGETRACE    0x00800000
    fmtcfg[0].defbit[0x18] = 82;    /// UECL1_USERTRACE     0x01000000
    fmtcfg[0].defbit[0x19] = 0;
    fmtcfg[0].defbit[0x1a] = 0;
    fmtcfg[0].defbit[0x1b] = 0;
    fmtcfg[0].defbit[0x1c] = 0;
    fmtcfg[0].defbit[0x1d] = 0;
    fmtcfg[0].defbit[0x1e] = 0;
    fmtcfg[0].defbit[0x1f] = 0;

    /*
     * leaf 1: extended
     */
    fmtcfg[1].rank = 1;
    fmtcfg[1].and_mask = UEC_LEAF0 | UEC_LEAF1 | UEC_LEAF2 | UEC_LEAF3;
    fmtcfg[1].cmp_mask = UEC_LEAF1;
    fmtcfg[1].defcount = 0x20;

    fmtcfg[1].defbit[0x00] = 8; /// UECL1_EXT_CPUFREQ   0x00000001
    fmtcfg[1].defbit[0x01] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x02] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x03] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x04] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x05] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x06] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x07] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x08] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x09] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0a] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0b] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0c] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0d] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0e] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x0f] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x10] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x11] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x12] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x13] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x14] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x15] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x16] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x17] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x18] = VTSS_FMTCFG_RESERVED;
    fmtcfg[1].defbit[0x19] = 0;
    fmtcfg[1].defbit[0x1a] = 0;
    fmtcfg[1].defbit[0x1b] = 0;
    fmtcfg[1].defbit[0x1c] = 0;
    fmtcfg[1].defbit[0x1d] = 0;
    fmtcfg[1].defbit[0x1e] = 0;
    fmtcfg[1].defbit[0x1f] = 0;
}

static void vtss_syscfg_init(void)
{
    vtss_syscfg_t *sysptr = &syscfg;
    struct new_utsname *u = init_utsname();

    /// sysinfo
    syscfg.version = 1;
    syscfg.major = (short)((LINUX_VERSION_CODE>>16) & 0xff);
    syscfg.minor = (short)((LINUX_VERSION_CODE>>8) & 0xff);
    syscfg.spack = (short)0;
    syscfg.extra = (short)(LINUX_VERSION_CODE & 0xff);
#if defined(CONFIG_X86_32)
    syscfg.type  = VTSS_LINUX_IA32;
#elif defined(CONFIG_X86_64)
    syscfg.type  = VTSS_LINUX_EM64T;
#else
    syscfg.type  = VTSS_UNKNOWN_ARCH;
#endif

    /// host name
    TRACE("nodename='%s'", u->nodename);
    sysptr->len = 1 + strlen(u->nodename);
    memcpy(sysptr->host_name, u->nodename, sysptr->len);
    sysptr = (vtss_syscfg_t*)((char*)sysptr + sysptr->len + sizeof(short));

    /// platform brand name
    TRACE("sysname='%s'", u->sysname);
    TRACE("machine='%s'", u->machine);
    sysptr->len = 1 + strlen(u->sysname);
    memcpy(sysptr->brand_name, u->sysname, sysptr->len);
    sysptr = (vtss_syscfg_t*)((char*)sysptr + sysptr->len + sizeof(short));

    /// system ID string
    TRACE("release='%s'", u->release);
    TRACE("version='%s'", u->version);
    sysptr->len = 1 + strlen(u->release);
    memcpy(sysptr->sysid_string, u->release, sysptr->len);
    sysptr = (vtss_syscfg_t*)((char*)sysptr + sysptr->len + sizeof(short));
    REPORT("Kernel version %s", u->release);

    /// root directory
    sysptr->len = 2; /* 1 + strlen("/") */
    memcpy(sysptr->system_root_dir, "/", sysptr->len);
    sysptr = (vtss_syscfg_t*)((char*)sysptr + sysptr->len + sizeof(short));

    syscfg.record_size = (int)((char *)sysptr - (char *)&syscfg + (char *)&syscfg.len - (char *)&syscfg);
}

union cpuid_01H_eax
{
    struct
    {
        unsigned int stepping:4;
        unsigned int model:4;
        unsigned int family:4;
        unsigned int type:2;
        unsigned int reserved1:2;
        unsigned int model_ext:4;
        unsigned int family_ext:8;
        unsigned int reserved2:4;
    } split;
    unsigned int full;
};

union cpuid_01H_ebx
{
    struct
    {
        unsigned int brand_index:8;
        unsigned int cache_line_size:8;
        unsigned int unit_no:8;
        unsigned int reserved:8;
    } split;
    unsigned int full;
};

union cpuid_04H_eax
{
    struct
    {
        unsigned int reserved:14;
        unsigned int smt_no:12;
        unsigned int core_no:6;
    } split;
    unsigned int full;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#define vtss_ktime_equal(cmp1, cmp2) ktime_equal(cmp1, cmp2)
#else
#define vtss_ktime_equal(cmp1, cmp2) ((cmp1) == (cmp2))
#endif

static void vtss_hardcfg_init(void)
{
    int cpu;
    union cpuid_01H_eax eax1;
    union cpuid_01H_ebx ebx1;
    union cpuid_04H_eax eax4;
    unsigned int ebx, ecx, edx;
    int thread_no = 0;
    int ht_supported = 0;
    int max_cpu_id = 0;

    /* Global variable vtss_time_source affects result of vtss_*_real() */
    vtss_time_source = 0;
    if (vtss_ktime_equal(KTIME_MONOTONIC_RES, KTIME_LOW_RES)) {
        INFO("An accuracy of kernel timer is not enough. Switch to TSC.");
        vtss_time_source = 1;
    }
    hardcfg.timer_freq = vtss_freq_real(); /* should be after change vtss_time_source */
    hardcfg.cpu_freq   = vtss_freq_cpu();
    hardcfg.version = 0x0002;
    // for 32 bits is like 0xC0000000
    // for 64 bits is like 0xffff880000000000
    hardcfg.maxusr_address = PAGE_OFFSET; /*< NOTE: Will be changed in vtss_record_configs() */
    /// initialize execution mode, OS version, and CPU ID parameters
#if defined(CONFIG_X86_32)
    hardcfg.mode    = 32;
    hardcfg.os_type = VTSS_LINUX_IA32;
#elif defined(CONFIG_X86_64)
    hardcfg.mode    = 64;
    hardcfg.os_type = VTSS_LINUX_EM64T;
#else
    hardcfg.mode    = 0;
    hardcfg.os_type = VTSS_UNKNOWN_ARCH;
#endif
    hardcfg.os_major = 0;
    hardcfg.os_minor = 0;
    hardcfg.os_sp    = 0;

    cpuid(0x01, &eax1.full, &ebx1.full, &ecx, &edx);

    hardcfg.family = eax1.split.family;
    if (eax1.split.family == 0x0f)
        hardcfg.family += eax1.split.family_ext;
    hardcfg.model = eax1.split.model;
    if (eax1.split.family == 0x06 || eax1.split.family == 0x0f)
        hardcfg.model += (eax1.split.model_ext << 4);
    hardcfg.stepping = eax1.split.stepping;
    ht_supported = ((edx >> 28) & 1) ? 1 : 0;

    cpuid(0x04, &eax4.full, &ebx, &ecx, &edx);

    for_each_present_cpu(cpu) {
        if (cpu_present(cpu)) {
            if (cpu > max_cpu_id) {
                max_cpu_id = cpu;
            }
        }
    }
    if (max_cpu_id + 1 > num_present_cpus()) {
        hardcfg.cpu_no = max_cpu_id + 1;
    }
    else {
        hardcfg.cpu_no = num_present_cpus();
    }
    if (hardcfg.cpu_no == 1) {
        thread_no = 1;
    } else {
        if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
            thread_no = eax4.split.smt_no + 1;
        }
        thread_no = thread_no ? thread_no : 1;
    }
    REPORT("Detected %d CPUs", hardcfg.cpu_no);
    REPORT("CPU family: 0x%02x, model: 0x%02x, stepping: %02x, HT: %s",
        hardcfg.family, hardcfg.model, hardcfg.stepping, ht_supported ? "yes" : "no");

    /*
     * build cpu map - distribute the current thread to all CPUs
     * to compute CPU IDs for asymmetric system configurations
     */
    for_each_present_cpu(cpu) {
        struct cpuinfo_x86 *c = &cpu_data(cpu);

        hardcfg.cpu_map[cpu].node   = cpu_to_node(cpu);
        hardcfg.cpu_map[cpu].pack   = c->phys_proc_id;
        hardcfg.cpu_map[cpu].core   = c->cpu_core_id;
        hardcfg.cpu_map[cpu].thread = c->initial_apicid & (thread_no - 1);
        TRACE("cpu[%d]: node=%d, pack=%d, core=%d, thread=%d",
                cpu, hardcfg.cpu_map[cpu].node, hardcfg.cpu_map[cpu].pack,
                hardcfg.cpu_map[cpu].core, hardcfg.cpu_map[cpu].thread);
    }
}

void vtss_reqcfg_init(void)
{
    int i = 0;
    memset(&reqcfg, 0, sizeof(process_cfg_t));
    for (i = 0; i < vtss_stk_last; i++) {
        reqcfg.stk_sz[i] = (unsigned long)-1;
        reqcfg.stk_pg_sz[i] = 0;
    }
}

int vtss_reqcfg_verify(void)
{
    if (reqcfg.cpuevent_count_v1 == 0 && (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH))
        return -1;
    return 0;
}

#define extract_bits(val, pos, len) (((val) >> (pos)) & ((1 << (len)) - 1))

static void vtss_iptcfg_init(void)
{
    unsigned int eax, ebx, ecx, edx;
    memset(&iptcfg, 0, sizeof(iptcfg));

    if (vtss_ipt_available() > 1)
    {
        iptcfg.version = 0;
        iptcfg.fratio = extract_bits((unsigned)read_msr(0xce), 8, 8);
        cpuid(0x15, &eax, &ebx, &ecx, &edx);
        iptcfg.ctcnom = ebx;
        iptcfg.tscdenom = eax;
        iptcfg.mtcfreq = 0;
    }
}

static void vtss_lookup_old_rsp(void)
{
    vtss_syscall_rsp_ptr = vtss_kallsyms_lookup_name("old_rsp");
    if (!vtss_syscall_rsp_ptr) vtss_syscall_rsp_ptr = vtss_kallsyms_lookup_name("per_cpu__old_rsp");
    if (!vtss_syscall_rsp_ptr) vtss_syscall_rsp_ptr = vtss_kallsyms_lookup_name("rsp_scratch");
}

void vtss_globals_fini(void)
{
    int cpu;

#ifndef VTSS_USE_NMI
    vtss_apic_fini();
#endif
    for_each_possible_cpu(cpu) {
        vtss_pcb_t* ppcb = &pcb(cpu);
        if (ppcb->scratch_ptr != NULL)
            kfree(ppcb->scratch_ptr);
        ppcb->scratch_ptr = NULL;
    }
}

int vtss_globals_init(void)
{
    int cpu;

    memset(&syscfg,  0, sizeof(vtss_syscfg_t));
    memset(&hardcfg, 0, sizeof(vtss_hardcfg_t));
    memset(&fmtcfg,  0, sizeof(fmtcfg_t)*2);
    memset(&reqcfg,  0, sizeof(process_cfg_t));
    for_each_possible_cpu(cpu) {
        vtss_pcb_t* ppcb = &pcb(cpu);
        memset(ppcb, 0, sizeof(vtss_pcb_t));
        ppcb->scratch_ptr = kmalloc_node(VTSS_DYNSIZE_SCRATCH, GFP_KERNEL, cpu_to_node(cpu));
        if (ppcb->scratch_ptr == NULL)
            goto fail;
    }
#ifndef VTSS_USE_NMI
    vtss_apic_init(); /* Need for vtss_hardcfg_init() */
#endif
    vtss_syscfg_init();
    vtss_hardcfg_init();
    vtss_iptcfg_init();
    vtss_fmtcfg_init();
    vtss_lookup_old_rsp();
    return 0;

fail:
    for_each_possible_cpu(cpu) {
        vtss_pcb_t* ppcb = &pcb(cpu);
        if (ppcb->scratch_ptr != NULL)
            kfree(ppcb->scratch_ptr);
        ppcb->scratch_ptr = NULL;
    }
    ERROR("No memory for PCB scratch");
    return VTSS_ERR_NOMEMORY;
}

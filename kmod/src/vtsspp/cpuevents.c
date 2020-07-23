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
#include "cpuevents.h"
#include "globals.h"
#include "collector.h"
#include "apic.h"
#include "time.h"

#include <linux/linkage.h>      /* for asmlinkage */
#include <linux/interrupt.h>
#include <asm/desc.h>           /* for gate_desc  */
#include <asm/uaccess.h>

/*
 * PMU macro definitions
 */
#define CPU_EVENTS_SUPPORTED 3
#define CPU_CLKEVT_THRESHOLD 5000LL
#define CPU_EVTCNT_THRESHOLD 0x80000000LL

#define VTSS_IA32_DEBUGCTL 0x1d9

#define VTSS_IA32_FIXED_CTR0            0x309
#define VTSS_IA32_FIXED_CTR_CTRL        0x38d
#define VTSS_IA32_PERF_GLOBAL_STATUS    0x38e
#define VTSS_IA32_PERF_GLOBAL_CTRL      0x38f
#define VTSS_IA32_PERF_GLOBAL_OVF_CTRL  0x390

#define VTSS_IA32_PERFEVTSEL0   0x186
#define VTSS_IA32_PMC0          0x0c1

#define VTSS_MSR_OFFCORE_RSP_0  0x1a6
#define VTSS_MSR_PEBS_LD_LAT    0x3f6
#define VTSS_MSR_PEBS_FRONTEND  0x3f7

/**
 * Globals for CPU Monitoring Functionality
 */
static int pmu_counter_no    = 0;
static int pmu_counter_width = 0;
static unsigned long long pmu_counter_width_mask = 0x000000ffffffffffULL;

static int pmu_fixed_counter_no    = 0;
static int pmu_fixed_counter_width = 0;
static unsigned long long pmu_fixed_counter_width_mask = 0x000000ffffffffffULL;
static atomic_t  vtss_cpuevents_active = ATOMIC_INIT(0);

/// event descriptors
cpuevent_desc_t cpuevent_desc[CPU_EVENTS_SUPPORTED];

extern void vtss_perfvec_handler(void);

void vtss_cpuevents_enable(void)
{
    if (!atomic_read(&vtss_cpuevents_active)) return;
    vtss_pmi_enable();
    /* enable counters globally (required for some Core2 & Core i7 systems) */
    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        unsigned long long mask = (((1ULL << pmu_fixed_counter_no) - 1) << 32) | ((1ULL << pmu_counter_no) - 1);

        TRACE("MSR(0x%x)<=0x%llx", VTSS_IA32_PERF_GLOBAL_CTRL, mask);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL, mask);
        mask |= 3ULL << 62;
        TRACE("MSR(0x%x)<=0x%llx", VTSS_IA32_PERF_GLOBAL_OVF_CTRL, mask);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, mask);
    }
}

void vtss_cpuevents_stop(void)
{
    if (cpuevent_desc[0].vft) {
        cpuevent_desc[0].vft->stop(NULL);
    }
}

void vtss_cpuevents_freeze(void)
{
    if (cpuevent_desc[0].vft) {
        cpuevent_desc[0].vft->freeze(NULL);
    }
}

#include "cpuevents_p6.h"
#include "cpuevents_sys.h"

void vtss_cpuevents_reqcfg_default(int need_clear, int defsav)
{
    int i, len0, len1;
    int mux_cnt = 0;
    int namespace_size = 0;

    if (need_clear) {
        memset(&reqcfg, 0, sizeof(process_cfg_t));
        reqcfg.trace_cfg.trace_flags =  VTSS_CFGTRACE_CTX    | VTSS_CFGTRACE_CPUEV   |
                                        VTSS_CFGTRACE_SWCFG  | VTSS_CFGTRACE_HWCFG   |
                                        VTSS_CFGTRACE_SAMPLE | VTSS_CFGTRACE_OSEV    |
                                        VTSS_CFGTRACE_MODULE | VTSS_CFGTRACE_PROCTHR |
                                        VTSS_CFGTRACE_STACKS | VTSS_CFGTRACE_TREE;
    }
    for (i = 0; i < CPU_EVENTS_SUPPORTED; i++) {
        if (i > 1 && hardcfg.family != 0x06)
            break;

        len0 = (int)strlen(cpuevent_desc[i].name)+1;
        len1 = (int)strlen(cpuevent_desc[i].desc)+1;

        if (namespace_size + len0 + len1 >= VTSS_CFG_SPACE_SIZE * 16)
            break;

        TRACE("Add cpuevent[%02d]: '%s' into mux_grp=%d", reqcfg.cpuevent_count_v1, cpuevent_desc[i].name, mux_cnt);
        /// copy event name
        memcpy(&reqcfg.cpuevent_namespace_v1[namespace_size], cpuevent_desc[i].name, len0);
        /// adjust event record
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].name_off = (int)((size_t)&reqcfg.cpuevent_namespace_v1[namespace_size] - (size_t)&reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1]);
        /// adjust namespace size
        namespace_size += len0;
        /// copy event description
        memcpy(&reqcfg.cpuevent_namespace_v1[namespace_size], cpuevent_desc[i].desc, len1);
        /// adjust event record
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].desc_off = (int)((size_t)&reqcfg.cpuevent_namespace_v1[namespace_size] - (size_t)&reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1]);
        /// adjust namespace size
        namespace_size += len1;

        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].name_len = len0;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].desc_len = len1;

        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].event_id = i;
        if (defsav) {
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].interval = defsav;
        } else if (hardcfg.family == VTSS_FAM_P6) {
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].interval = 2000000;
        } else {
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].interval = 10000000;
        }
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].mux_grp  = mux_cnt;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].mux_alg  = VTSS_CFGMUX_SEQ;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].mux_arg  = 1;

        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].selmsr.idx = cpuevent_desc[i].selmsr;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].selmsr.val = cpuevent_desc[i].selmsk;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].selmsr.msk = 0;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].cntmsr.idx = cpuevent_desc[i].cntmsr;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].cntmsr.val = 0;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].cntmsr.msk = 0;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].extmsr.idx = cpuevent_desc[i].extmsr;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].extmsr.val = cpuevent_desc[i].extmsk;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].extmsr.msk = 0;

        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].reqtype = VTSS_CFGREQ_CPUEVENT_V1;
        reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].reqsize = sizeof(cpuevent_cfg_v1_t) + len0 + len1;
        reqcfg.cpuevent_count_v1++;
    }
}

void vtss_sysevents_reqcfg_append(void)
{
    int i, j;
    int mux_grp = 0;
    int namespace_size = 0;

    const int idle_idx = 2;
    const int idle_last = 8;
    const int active_idx = 9;
    const int active_last = 13;
    int sys_event_idx = 2;

    /* Find out the count of mux groups and namespace size */
    for (i = 0; i < reqcfg.cpuevent_count_v1; i++) {
        mux_grp = (mux_grp < reqcfg.cpuevent_cfg_v1[i].mux_grp) ? reqcfg.cpuevent_cfg_v1[i].mux_grp : mux_grp;
        namespace_size += reqcfg.cpuevent_cfg_v1[i].name_len + reqcfg.cpuevent_cfg_v1[i].desc_len;
    }
    /* insert system event records (w/names) into each mux_grp */
    for (i = sys_event_idx; i < vtss_sysevent_end && reqcfg.cpuevent_count_v1 < VTSS_CFG_CHAIN_SIZE; i++) {

        if (sysevent_type[i] == vtss_sysevent_end) {
            /* skip events that are not supported on this architecture */
            continue;
        }
        if (i >= idle_idx && i <= idle_last && (!(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_PWRIDLE))) {
            // idle power not required
            continue;
        }
        if (i >= active_idx && i <= active_last && (!(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_PWRACT))) {
            // active power not required
            continue;
        }
        for (j = 0; j <= mux_grp && reqcfg.cpuevent_count_v1 < VTSS_CFG_CHAIN_SIZE; j++) {
            int len0 = (int)strlen(sysevent_desc[i].name)+1;
            int len1 = (int)strlen(sysevent_desc[i].desc)+1;

            if (namespace_size + len0 + len1 >= VTSS_CFG_SPACE_SIZE * 16) {
                i = vtss_sysevent_end;
                break;
            }

            TRACE("Add sysevent[%02d]: '%s' into mux_grp=%d of %d", reqcfg.cpuevent_count_v1, sysevent_desc[i].name, j, mux_grp);
            /// copy event name
            memcpy(&reqcfg.cpuevent_namespace_v1[namespace_size], sysevent_desc[i].name, len0);
            /// adjust event record
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].name_off = (int)((size_t)&reqcfg.cpuevent_namespace_v1[namespace_size] - (size_t)&reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1]);
            /// adjust namespace size
            namespace_size += len0;
            /// copy event description
            memcpy(&reqcfg.cpuevent_namespace_v1[namespace_size], sysevent_desc[i].desc, len1);
            /// adjust event record
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].desc_off = (int)((size_t)&reqcfg.cpuevent_namespace_v1[namespace_size] - (size_t)&reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1]);
            /// adjust namespace size
            namespace_size += len1;

            /// copy event record
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].name_len = len0;
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].desc_len = len1;
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].mux_grp  = j;
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].event_id = i + VTSS_CFG_CHAIN_SIZE;
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].interval = 0;

            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].reqtype = VTSS_CFGREQ_CPUEVENT_V1;
            reqcfg.cpuevent_cfg_v1[reqcfg.cpuevent_count_v1].reqsize = sizeof(cpuevent_cfg_v1_t) + len0 + len1;
            reqcfg.cpuevent_count_v1++;
        }
    }
}

static void vtss_cpuevents_validate_event(cpuevent_t* event, char *name)
{
    if ((event->selmsr < VTSS_IA32_PERFEVTSEL0 || event->selmsr >= VTSS_IA32_PERFEVTSEL0 + pmu_counter_no) &&
        event->selmsr != VTSS_IA32_FIXED_CTR_CTRL)
    {
        ERROR("%s: Bad event select MSR: 0x%x", name, event->selmsr);
        event->selmsr = VTSS_IA32_PERFEVTSEL0;
        event->selmsk = 0;
        event->cntmsr = VTSS_IA32_PMC0;
    }
    if ((event->cntmsr < VTSS_IA32_PMC0       || event->cntmsr >= VTSS_IA32_PMC0       + pmu_counter_no) &&
        (event->cntmsr < VTSS_IA32_FIXED_CTR0 || event->cntmsr >= VTSS_IA32_FIXED_CTR0 + pmu_counter_no))
    {
        ERROR("%s: Bad control MSR: 0x%x", name, event->cntmsr);
        event->selmsr = VTSS_IA32_PERFEVTSEL0;
        event->selmsk = 0;
        event->cntmsr = VTSS_IA32_PMC0;
    }
    if (event->extmsr && (event->extmsr != VTSS_MSR_OFFCORE_RSP_0 && event->extmsr != VTSS_MSR_OFFCORE_RSP_0 + 1 &&
                          event->extmsr != VTSS_MSR_PEBS_LD_LAT   && event->extmsr != VTSS_MSR_PEBS_FRONTEND))
    {
        ERROR("%s: Bad extra MSR: 0x%x", name, event->extmsr);
        event->extmsr = 0;
        event->extmsk = 0;
    }
}

// called from process_init() to form a common event chain from the configuration records
void vtss_cpuevents_upload(cpuevent_t* cpuevent_chain, cpuevent_cfg_v1_t* cpuevent_cfg, int count)
{
    int i = 0;
    int j = 0;
    int mux_cnt = 0;
    int fixed_cnt[3];
    int fixed_cnt_slave = 0;

    fixed_cnt[0] = fixed_cnt[1] = fixed_cnt[2] = -1;

    for (i = 0; i < count; i++) {
        cpuevent_chain[i].valid = 1;
        if (reqcfg.ipt_cfg.mode & vtss_iptmode_full) {
            cpuevent_cfg[i].interval = 0;
            cpuevent_cfg[i].cntmsr.val = 0;
        }
        if (cpuevent_cfg[i].event_id >= VTSS_CFG_CHAIN_SIZE) {
            /// fake sysevents
            cpuevent_chain[i].vft      = &vft_sys;
            cpuevent_chain[i].interval = sysevent_type[cpuevent_cfg[i].event_id - VTSS_CFG_CHAIN_SIZE];
            cpuevent_chain[i].modifier = 0;
        } else {
            cpuevent_chain[i].vft      = cpuevent_desc[0].vft;
            cpuevent_chain[i].interval = cpuevent_cfg[i].interval;
            cpuevent_chain[i].slave_interval = 0;

            /// copy MSRs
            cpuevent_chain[i].selmsr = cpuevent_cfg[i].selmsr.idx;
            cpuevent_chain[i].selmsk = cpuevent_cfg[i].selmsr.val;
            cpuevent_chain[i].cntmsr = cpuevent_cfg[i].cntmsr.idx;
            cpuevent_chain[i].extmsr = cpuevent_cfg[i].extmsr.idx;
            cpuevent_chain[i].extmsk = cpuevent_cfg[i].extmsr.val;

            if (cpuevent_cfg[i].name_len) {
                /* replace BR_INST_RETIRED.NEAR_CALL_R3_PS event */
                int name_len = cpuevent_cfg[i].name_len > 32 ? 32 : cpuevent_cfg[i].name_len;
                if (!memcmp(((char*)&cpuevent_cfg[i] + cpuevent_cfg[i].name_off),
                             "BR_INST_RETIRED.NEAR_CALL_R3_PS", name_len))
                {
                    cpuevent_cfg[i].name_len = 11; /* strlen("Call Count") + '\0' */
                    memcpy(((char*)&cpuevent_cfg[i] + cpuevent_cfg[i].name_off),
                           "Call Count", cpuevent_cfg[i].name_len);
                }
            }
            /// correct the sampling interval if not setup explicitly
            if (!cpuevent_chain[i].interval && cpuevent_cfg[i].cntmsr.val) {
                if ((cpuevent_chain[i].interval = -(int)(cpuevent_cfg[i].cntmsr.val | 0xffffffff00000000ULL)) < CPU_CLKEVT_THRESHOLD) {
                    cpuevent_chain[i].interval = CPU_CLKEVT_THRESHOLD * 400;
                }
                cpuevent_cfg[i].interval = cpuevent_chain[i].interval;
            }
            /// set up counter offset for fixed events
            if (hardcfg.family == VTSS_FAM_P6 && cpuevent_cfg[i].selmsr.idx == VTSS_IA32_FIXED_CTR_CTRL) {
                if (cpuevent_cfg[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0 < 3 && cpuevent_cfg[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0 >= 0)
                {
                    fixed_cnt[cpuevent_cfg[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0] = i;
                }
                /// form the modifier to enable correct masking of control MSR in vft->restart()
                cpuevent_chain[i].modifier = (int)((cpuevent_cfg[i].selmsr.val >>
                                                   (4 * (cpuevent_cfg[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0))) << 16);
                ((event_modifier_t*)&cpuevent_chain[i].modifier)->cnto = cpuevent_cfg[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0;
            } else {
                cpuevent_chain[i].modifier = (int)(cpuevent_cfg[i].selmsr.val & VTSS_EVMOD_ALL);
            }
            vtss_cpuevents_validate_event(cpuevent_chain + i, (char*)&cpuevent_cfg[i] + cpuevent_cfg[i].name_off);
        }
        cpuevent_chain[i].mux_grp = cpuevent_cfg[i].mux_grp;
        cpuevent_chain[i].mux_alg = cpuevent_cfg[i].mux_alg;
        cpuevent_chain[i].mux_arg = cpuevent_cfg[i].mux_arg;

        mux_cnt = (mux_cnt < cpuevent_chain[i].mux_grp) ? cpuevent_chain[i].mux_grp : mux_cnt;

        TRACE("Upload event[%02d]: '%s' .modifier=%x .selmsr=%x .cntmsr=%x .selmsk=%x",
              i, ((char*)&cpuevent_cfg[i] + cpuevent_cfg[i].name_off),
              cpuevent_chain[i].modifier, cpuevent_chain[i].selmsr,
              cpuevent_chain[i].cntmsr,   cpuevent_chain[i].selmsk
        );
    }

    for (j = 2; j>=0; j--) {
        if (fixed_cnt[j] == -1) continue;
        if (fixed_cnt_slave == 0) {
            fixed_cnt_slave = 1;
            continue;
        }
        /// set up fixed counter events as slaves (that follow leading events)
        cpuevent_chain[fixed_cnt[j]].slave_interval = cpuevent_cfg[fixed_cnt[j]].interval;
        cpuevent_chain[fixed_cnt[j]].interval = 0;
    }
    if (i) {
        cpuevent_chain[0].mux_cnt = mux_cnt;
    }
}

int vtss_cpuevents_get_sampling_interval(void)
{
    int i;

    for (i = 0; i < reqcfg.cpuevent_count_v1; i++) {
        if (hardcfg.family == VTSS_FAM_P6 && reqcfg.cpuevent_cfg_v1[i].selmsr.idx == VTSS_IA32_FIXED_CTR_CTRL) {
            if ((reqcfg.cpuevent_cfg_v1[i].cntmsr.idx - VTSS_IA32_FIXED_CTR0) == 2) {
                unsigned int sav = *(unsigned int*)&reqcfg.cpuevent_cfg_v1[i].interval;
                if (sav > 0 && hardcfg.cpu_freq > 0 && hardcfg.cpu_freq > sav) {
                    if (hardcfg.cpu_freq/sav < 1000)
                        return 1000/(hardcfg.cpu_freq/sav);
                }
            }
        }
    }
    return 1;
}

/// TODO: generate correct records for system-wide sampling/counting
/// called from swap_in(), pmi_handler(), and vtssreq_trigger()
/// to read event values and form a sample record
void vtss_cpuevents_sample(cpuevent_t* cpuevent_chain)
{
    int i;

    if (unlikely(!cpuevent_chain)) {
        ERROR("CPU event chain is empty");
        return;
    }

    /// select between thread-specific and per-processor chains (system-wide)
    for (i = 0; i < VTSS_CFG_CHAIN_SIZE && cpuevent_chain[i].valid; i++) {
        TRACE("[%02d]: mux_idx=%d, mux_grp=%d of %d %s", i,
              cpuevent_chain[i].mux_idx, cpuevent_chain[i].mux_grp, cpuevent_chain[0].mux_cnt,
              (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx) ? "skip" : ".vft->freeze_read()");
        if (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx)
            continue;
        cpuevent_chain[i].vft->freeze_read((cpuevent_t*)&cpuevent_chain[i]);
    }
}

/* this->tmp: positive - update and restart, negative - just restart
 *  0 - reset counter,
 *  1 - switch_to,
 *  2 - preempt,
 *  3 - sync,
 * -1 - switch_to no update,
 * -2 - preempt no update,
 * -3 - sync no update
 */
void vtss_cpuevents_quantum_border(cpuevent_t* cpuevent_chain, int flag)
{
    int i;
    if (unlikely(!cpuevent_chain)) {
        ERROR("CPU event chain is empty");
        return;
    }
    for (i = 0; i < VTSS_CFG_CHAIN_SIZE && cpuevent_chain[i].valid; i++) {
        TRACE("[%02d]: mux_idx=%d, mux_grp=%d of %d %s flag=%d", i,
              cpuevent_chain[i].mux_idx, cpuevent_chain[i].mux_grp, cpuevent_chain[i].mux_cnt,
              (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx) ? "skip" : ".vft->update_restart()", flag);
        if (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx)
            continue;
        cpuevent_chain[i].tmp = flag;
        cpuevent_chain[i].vft->update_restart((cpuevent_t*)&cpuevent_chain[i]);
    }
}

// called from swap_in() and pmi_handler()
// to re-select multiplexion groups and restart counting
void vtss_cpuevents_restart(cpuevent_t* cpuevent_chain, int flag)
{
    int i, j;
    long long muxchange_time = 0;
    int muxchange_alt = 0;
    int mux_idx = 0;
    int mux_cnt;
    int mux_alg;
    int mux_arg;
    int mux_flag;

    if (!atomic_read(&vtss_cpuevents_active)) return;
    vtss_cpuevents_enable();
    for (i = 0; i < VTSS_CFG_CHAIN_SIZE && cpuevent_chain[i].valid; i++) {
        /// update current MUX group in accordance with MUX algorithm
        /// and parameter restart counting for the active MUX group
        if (i == 0) {
            /// load MUX context
            muxchange_time = cpuevent_chain[0].muxchange_time;
            muxchange_alt  = cpuevent_chain[0].muxchange_alt;
            mux_idx = cpuevent_chain[0].mux_idx;
            mux_cnt = cpuevent_chain[0].mux_cnt;
            mux_alg = cpuevent_chain[0].mux_alg;
            mux_arg = cpuevent_chain[0].mux_arg;

            /// update current MUX index
            switch (mux_alg) {
            case VTSS_CFGMUX_NONE:
                /// no update to MUX index
                break;

            case VTSS_CFGMUX_TIME:
                if (!muxchange_time) {
                    /// setup new time interval
                    muxchange_time = vtss_time_cpu() + (mux_arg * hardcfg.cpu_freq);
                } else if (vtss_time_cpu() >= muxchange_time) {
                    mux_idx = (mux_idx + 1 > mux_cnt) ? 0 : mux_idx + 1;
                    muxchange_time = 0;
                }
                break;

            case VTSS_CFGMUX_MST:
            case VTSS_CFGMUX_SLV:
                for (j = 0, mux_flag = 0; j < VTSS_CFG_CHAIN_SIZE && cpuevent_chain[j].valid; j++) {
                    if (cpuevent_chain[j].mux_grp == mux_idx && cpuevent_chain[j].mux_alg == VTSS_CFGMUX_MST) {
                        if (cpuevent_chain[j].vft->overflowed((cpuevent_t*)&cpuevent_chain[j])) {
                            mux_flag = 1;
                            break;
                        }
                    }
                }
                if (!mux_flag) {
                    break;
                }
                /// else fall through

            case VTSS_CFGMUX_SEQ:
                if (!muxchange_alt) {
                    muxchange_alt = mux_arg;
                }
                if (!--muxchange_alt) {
                    mux_idx = (mux_idx + 1 > mux_cnt) ? 0 : mux_idx + 1;
                }
                break;

            default:
                /// erroneously configured, ignore
                break;
            }
        }

        /// save MUX context
        cpuevent_chain[i].muxchange_time = muxchange_time;
        cpuevent_chain[i].muxchange_alt  = muxchange_alt;
        cpuevent_chain[i].mux_idx        = mux_idx;

        TRACE("[%02d]: mux_idx=%d, mux_grp=%d of %d %s", i,
              cpuevent_chain[i].mux_idx, cpuevent_chain[i].mux_grp, cpuevent_chain[0].mux_cnt,
              (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx) ? "skip" : ".vft->restart()");
        /* restart counting */
        if (cpuevent_chain[i].mux_grp != cpuevent_chain[i].mux_idx)
            continue;
        cpuevent_chain[i].vft->restart((cpuevent_t*)&cpuevent_chain[i]);
    }
}

static void vtss_cpuevents_save(void *ctx)
{
    unsigned long flags;
#ifndef VTSS_USE_NMI
    gate_desc *idt_base;
    struct desc_ptr idt_ptr;
#endif

    local_irq_save(flags);
    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        rdmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, pcb_cpu.saved_msr_ovf);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, 0ULL);
        rdmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     pcb_cpu.saved_msr_perf);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     0ULL);
        rdmsrl(VTSS_IA32_DEBUGCTL,             pcb_cpu.saved_msr_debug);
        wrmsrl(VTSS_IA32_DEBUGCTL,             0ULL);
    }
#ifdef VTSS_USE_NMI
    pcb_cpu.saved_apic_lvtpc = apic_read(APIC_LVTPC);
    apic_write(APIC_LVTPC, APIC_DM_NMI);
#endif
#ifndef VTSS_USE_NMI
    store_idt(&idt_ptr);
    idt_base = (gate_desc*)idt_ptr.address;
    pcb_cpu.idt_base = idt_base;
    memcpy(&pcb_cpu.saved_perfvector, &idt_base[CPU_PERF_VECTOR], sizeof(gate_desc));
#endif
    local_irq_restore(flags);
}

static void vtss_cpuevents_stop_all(void *ctx)
{
    unsigned long flags;

    local_irq_save(flags);
    vtss_pmi_disable();
    vtss_cpuevents_stop();
    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, 0ULL);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     0ULL);
        wrmsrl(VTSS_IA32_DEBUGCTL,             0ULL);
    }
    local_irq_restore(flags);
}

static void vtss_cpuevents_restore(void *ctx)
{
    unsigned long flags;
#ifndef VTSS_USE_NMI
    gate_desc *idt_base;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    unsigned long cr0;
#endif
#endif

    local_irq_save(flags);
    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, pcb_cpu.saved_msr_ovf);
        wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     pcb_cpu.saved_msr_perf);
        wrmsrl(VTSS_IA32_DEBUGCTL,             pcb_cpu.saved_msr_debug);
    }
#ifdef VTSS_USE_NMI
    apic_write(APIC_LVTPC, pcb_cpu.saved_apic_lvtpc);
#endif

#ifndef VTSS_USE_NMI
    idt_base = pcb_cpu.idt_base;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
#endif
    write_idt_entry(idt_base, CPU_PERF_VECTOR, &pcb_cpu.saved_perfvector);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    write_cr0(cr0);
#endif
#endif

    local_irq_restore(flags);
}

#ifndef VTSS_USE_NMI
static void vtss_cpuevents_setup(void *ctx)
{
    unsigned long flags;
    gate_desc *idt_base, g;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    unsigned long cr0;
#endif
    local_irq_save(flags);
    idt_base = pcb_cpu.idt_base;
    pack_gate(&g, GATE_INTERRUPT, (unsigned long)vtss_perfvec_handler, 3, 0, __KERNEL_CS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
#endif
    write_idt_entry(idt_base, CPU_PERF_VECTOR, &g);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    write_cr0(cr0);
#endif

    local_irq_restore(flags);
}
#endif

#ifdef VTSS_USE_NMI
#include <asm/nmi.h>
#include <asm/apic.h>

void vtss_pmi_handler(struct pt_regs *regs);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
static int vtss_nmi_handler(unsigned int cmd, struct pt_regs *regs)
{
    int state = VTSS_COLLECTOR_STATE();

    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        wrmsrl(VTSS_IA32_DEBUGCTL, 0ULL);
    }
    if (state >= VTSS_COLLECTOR_RUNNING) {
        vtss_pmi_handler(regs);
        return NMI_HANDLED;
    }
    else if (state == VTSS_COLLECTOR_UNINITING) {
        return NMI_HANDLED;
    }
    return NMI_DONE;
}
#else
#include <linux/kdebug.h>
static int vtss_nmi_handler(struct notifier_block *self, unsigned long val, void *data)
{
    struct die_args *args = (struct die_args *)data;
    int state = VTSS_COLLECTOR_STATE();

    if (args) {
        switch (val) {
            case DIE_NMI:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
            case DIE_NMI_IPI:
#endif
                if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
                    wrmsrl(VTSS_IA32_DEBUGCTL, 0ULL);
                }
                if (state >= VTSS_COLLECTOR_RUNNING) {
                    vtss_pmi_handler(args->regs);
                    return NOTIFY_STOP;
                }
                else if (state == VTSS_COLLECTOR_UNINITING) {
                    return NOTIFY_STOP;
                }
        }
    }
    return NOTIFY_DONE;
}

static struct notifier_block vtss_notifier = {
    .notifier_call = vtss_nmi_handler,
    .next = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
    .priority = 2
#else
    .priority = NMI_LOCAL_LOW_PRIOR,
#endif
};
#endif
#endif

int vtss_cpuevents_init_pmu(int defsav)
{
    REPORT("PMU: uploading %d events", (int)reqcfg.cpuevent_count_v1);
    atomic_set(&vtss_cpuevents_active, 1);
    if (reqcfg.cpuevent_count_v1 == 0 && !(reqcfg.trace_cfg.trace_flags & (VTSS_CFGTRACE_CTX|VTSS_CFGTRACE_PWRACT|VTSS_CFGTRACE_PWRIDLE))) {
        /* There is no configuration was get from runtool, so init defaults */
        DEBUG_CPUEVT("There is no configuration was get from runtool, so init defaults");
        vtss_cpuevents_reqcfg_default(1, defsav);
        vtss_sysevents_reqcfg_append();
    }
#ifdef VTSS_USE_NMI
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
    register_nmi_handler(NMI_LOCAL, vtss_nmi_handler, 0, "vtss_pmi");
#else
    register_die_notifier(&vtss_notifier);
#endif
    REPORT("PMI: registered NMI handler");
#endif
    on_each_cpu(vtss_cpuevents_save,  NULL, SMP_CALL_FUNCTION_ARGS);
#ifndef VTSS_USE_NMI
    on_each_cpu(vtss_cpuevents_setup, NULL, SMP_CALL_FUNCTION_ARGS);
    REPORT("PMI: installed IDT vector 0x%x", CPU_PERF_VECTOR);
#endif
    return 0;
}

void vtss_cpuevents_fini_pmu(void)
{
    atomic_set(&vtss_cpuevents_active, 0);
    on_each_cpu(vtss_cpuevents_stop_all, NULL, SMP_CALL_FUNCTION_ARGS);
    on_each_cpu(vtss_cpuevents_restore,  NULL, SMP_CALL_FUNCTION_ARGS);
#ifdef VTSS_USE_NMI
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
    unregister_nmi_handler(NMI_LOCAL, "vtss_pmi");
#else
    unregister_die_notifier(&vtss_notifier);
#endif
#endif
}

union cpuid_0AH_eax
{
    struct
    {
        unsigned int version_id:8;
        unsigned int counters_no:8;
        unsigned int counters_width:8;
        unsigned int reserved:8;
    } split;
    unsigned int full;
};

union cpuid_0AH_edx
{
    struct
    {
        unsigned int fixed_counters_no:5;
        unsigned int fixed_counters_width:8;
        unsigned int reserved:29;
    } split;
    unsigned int full;
};

int vtss_cpuevents_init(void)
{
    int counter_offset = 0;

    if (hardcfg.family == VTSS_FAM_P6) {

        union cpuid_0AH_eax eax;
        union cpuid_0AH_edx edx;
        unsigned int ebx, ecx;

        cpuid(0x0a, &eax.full, &ebx, &ecx, &edx.full);

        pmu_counter_no    = eax.split.counters_no;
        pmu_counter_width = eax.split.counters_width;
        pmu_counter_width_mask = (1ULL << pmu_counter_width) - 1;

        pmu_fixed_counter_no    = edx.split.fixed_counters_no;
        pmu_fixed_counter_width = edx.split.fixed_counters_width;
        pmu_fixed_counter_width_mask = (1ULL << pmu_fixed_counter_width) - 1;

        counter_offset = (pmu_counter_no >= 4) ? VTSS_EVMOD_CNT3 : VTSS_EVMOD_CNT1;
    }
    REPORT("PMU: fixed counters: %d counters: %d", pmu_fixed_counter_no, pmu_counter_no);

    if (!pmu_counter_no) {
        ERROR("PMU counters are not detected");
        hardcfg.family = VTSS_UNKNOWN_ARCH;
        return VTSS_ERR_NOSUPPORT;
    }

    memset(cpuevent_desc, 0, sizeof(cpuevent_desc));
    if (hardcfg.family == VTSS_FAM_P6) {
        TRACE("P6-cpuevents is used");
        cpuevent_desc[0].event_id = VTSS_EVID_FIXED_INSTRUCTIONS_RETIRED;
        cpuevent_desc[0].vft      = &vft_p6;
        cpuevent_desc[0].name     = "INST_RETIRED.ANY";
        cpuevent_desc[0].desc     = "INST_RETIRED.ANY";
        cpuevent_desc[0].modifier = VTSS_EVMOD_ALL | counter_offset;
        cpuevent_desc[0].selmsr   = VTSS_IA32_FIXED_CTR_CTRL;
        cpuevent_desc[0].cntmsr   = VTSS_IA32_FIXED_CTR0;
        cpuevent_desc[0].selmsk   = 0x0000000b;

        cpuevent_desc[1].event_id = VTSS_EVID_FIXED_NONHALTED_CLOCKTICKS;
        cpuevent_desc[1].vft      = &vft_p6;
        cpuevent_desc[1].name     = "CPU_CLK_UNHALTED.THREAD";
        cpuevent_desc[1].desc     = "CPU_CLK_UNHALTED.THREAD";
        cpuevent_desc[1].modifier = VTSS_EVMOD_ALL | counter_offset;
        cpuevent_desc[1].selmsr   = VTSS_IA32_FIXED_CTR_CTRL;
        cpuevent_desc[1].cntmsr   = VTSS_IA32_FIXED_CTR0+1;
        cpuevent_desc[1].selmsk   = 0x000000b0;

        cpuevent_desc[2].event_id = VTSS_EVID_FIXED_NONHALTED_REFTICKS;
        cpuevent_desc[2].vft      = &vft_p6;
        cpuevent_desc[2].name     = "CPU_CLK_UNHALTED.REF";
        cpuevent_desc[2].desc     = "CPU_CLK_UNHALTED.REF";
        cpuevent_desc[2].modifier = VTSS_EVMOD_ALL | counter_offset;
        cpuevent_desc[2].selmsr   = VTSS_IA32_FIXED_CTR_CTRL;
        cpuevent_desc[2].cntmsr   = VTSS_IA32_FIXED_CTR0+2;
        cpuevent_desc[2].selmsk   = 0x00000b00;

        /* CPU BUG: broken fixed counters on some Meroms and Penryns */
        if (hardcfg.model == VTSS_CPU_MRM && hardcfg.stepping < 0x0b) {
            ERROR("All fixed counters are broken");
        } else if (hardcfg.model == VTSS_CPU_PNR) {
            ERROR("CPU_CLK_UNHALTED.REF fixed counter is broken");
        }

        { /* check for read-only counter mode */
            unsigned long long tmp, tmp1;

            wrmsrl(VTSS_IA32_PERFEVTSEL0, 0ULL);
            wrmsrl(VTSS_IA32_PMC0, 0ULL);
            rdmsrl(VTSS_IA32_PMC0, tmp);
            tmp |= 0x7f00ULL;
            wrmsrl(VTSS_IA32_PMC0, tmp);
            rdmsrl(VTSS_IA32_PMC0, tmp1);
            if (tmp1 != tmp) {
                /* read-only counters, change the event VFT */
                REPORT("Read-only counter mode detected");
                vft_p6.restart     = vf_p6_restart_ro;
                vft_p6.freeze_read = vf_p6_freeze_read_ro;
            }
            wrmsrl(VTSS_IA32_PMC0, 0ULL);
        }
    }
    /// TODO: validate SNB and MFLD energy meters:
    /// sysevent_type[vtss_sysevent_energy_xxx] = vtss_sysevent_end if not present
    DEBUG_CPUEVT("family=%x, model=%x", hardcfg.family,hardcfg.model);
    if (hardcfg.family == VTSS_FAM_P6) {
        if (hardcfg.model == VTSS_CPU_SNB ||
           hardcfg.model == VTSS_CPU_IVB ||
           hardcfg.model == VTSS_CPU_HSW ||
           hardcfg.model == VTSS_CPU_BDW ||
           hardcfg.model == VTSS_CPU_BDW_GT3 ||
           hardcfg.model == VTSS_CPU_HSW_ULT ||
           hardcfg.model == VTSS_CPU_HSW_GT3)
        {
            sysevent_type[vtss_sysevent_energy_dram] = vtss_sysevent_end;
        } else if (hardcfg.model == VTSS_CPU_HSW_X) {
            sysevent_type[vtss_sysevent_energy_core] = vtss_sysevent_end;
            sysevent_type[vtss_sysevent_energy_gfx]  = vtss_sysevent_end;
        } else if (hardcfg.model == VTSS_CPU_SNB_X  || hardcfg.model == VTSS_CPU_IVB_X) {
            sysevent_type[vtss_sysevent_energy_gfx]  = vtss_sysevent_end;
        } else {
            sysevent_type[vtss_sysevent_energy_core] = vtss_sysevent_end;
            sysevent_type[vtss_sysevent_energy_gfx]  = vtss_sysevent_end;
            sysevent_type[vtss_sysevent_energy_pack] = vtss_sysevent_end;
            sysevent_type[vtss_sysevent_energy_dram] = vtss_sysevent_end;
        }
    } else {
        sysevent_type[vtss_sysevent_energy_core] = vtss_sysevent_end;
        sysevent_type[vtss_sysevent_energy_gfx]  = vtss_sysevent_end;
        sysevent_type[vtss_sysevent_energy_pack] = vtss_sysevent_end;
        sysevent_type[vtss_sysevent_energy_dram] = vtss_sysevent_end;
    }
    sysevent_type[vtss_sysevent_energy_soc] = vtss_sysevent_end;
    /* TODO: Not implemeted. Turn off for Linux now all idle_* */
    sysevent_type[vtss_sysevent_idle_time]   = vtss_sysevent_end;
    sysevent_type[vtss_sysevent_idle_wakeup] = vtss_sysevent_end;
    sysevent_type[vtss_sysevent_idle_c3]     = vtss_sysevent_end;
    sysevent_type[vtss_sysevent_idle_c6]     = vtss_sysevent_end;
    sysevent_type[vtss_sysevent_idle_c7]     = vtss_sysevent_end;
    return 0;
}

void vtss_cpuevents_fini(void)
{
    pmu_counter_no         = 0;
    pmu_counter_width      = 0;
    pmu_counter_width_mask = 0x000000ffffffffffULL;

    pmu_fixed_counter_no         = 0;
    pmu_fixed_counter_width      = 0;
    pmu_fixed_counter_width_mask = 0x000000ffffffffffULL;

    hardcfg.family = VTSS_UNKNOWN_ARCH;
}

#define VTSS_CLR_PEBS_OVF        0x4000000000000000ULL
#define VTSS_CLR_STATUS_PEBS_OVF 0x4000000000000000ULL

int vtss_cpuevents_clr_pebs_ovf(void)
{
    unsigned long long val = 0;

    if (hardcfg.family == VTSS_FAM_P6 && hardcfg.model >= VTSS_CPU_MRM) {
        rdmsrl(VTSS_IA32_PERF_GLOBAL_STATUS, val);
        if (val & VTSS_CLR_STATUS_PEBS_OVF) {
            wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, VTSS_CLR_PEBS_OVF);
            return 1;
        }
    }
    return 0;
}

void vtss_set_pce(void *arg)
{
    int to_val = (arg != 0);
    unsigned long cr4_val = 0;

    cr4_val = native_read_cr4();
    if (to_val)
    {
        pcb_cpu.pce_state = cr4_val & X86_CR4_PCE;
        cr4_val |= X86_CR4_PCE;
    }
    else if (!pcb_cpu.pce_state)
    {
        cr4_val &= ~X86_CR4_PCE;
    }
    native_write_cr4(cr4_val);
}

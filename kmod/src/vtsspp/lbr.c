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
#include "transport.h"
#include "unwind.h"
#include "lbr.h"
#include "record.h"
#include "time.h"

#define DEBUGCTL_MSR        0x01d9
#define LBR_ENABLE_MASK_P4  0x0021
#define LBR_ENABLE_MASK_P6  0x0201  ///0x0001
#define LBR_ENABLE_MASK_HSW 0x0201
#define LBR_SELECT_MASK_HSW 0x03c5

int vtss_lbr_no       = 0;
int vtss_lbr_msr_ctl  = 0;
int vtss_lbr_msr_from = 0;
int vtss_lbr_msr_to   = 0;
int vtss_lbr_msr_tos  = 0;
int vtss_lbr_msr_sel  = 0;

/// clear stack trace record
static long long read_msr(int idx)
{
    long long val;
    rdmsrl(idx, val);
    return val;
}

int vtss_stack_record_lbr(struct vtss_transport_data* trnd, stack_control_t* stk, pid_t tid, int cpu, int is_safe)
{
    int rc = 0;
    int i, j, k;
    int lbridx;

    int sign;
    int prefix;
    size_t value;
    size_t offset;

    size_t ip = 0;

    char* compressed = stk->compressed;

    i = 0;
    /// loop through all LBRs, form a 'clear' stack record, and save it
    if (vtss_lbr_no && !vtss_lbr_msr_ctl)
    {
        lbridx = read_msr(vtss_lbr_msr_tos) & (vtss_lbr_no - 1);

        for (i = 0, k = 0; k < vtss_lbr_no && i < (stk->size >> 1); k++)
        {
            value = (size_t)((read_msr(vtss_lbr_msr_from + lbridx) << 16) >> 16);

            if (!value)
            {
                break;
            }

            offset = ip;
            ip = value;
            prefix = 0;
            value -= offset;

            sign = (value & (((size_t)1) << ((sizeof(size_t) << 3) - 1))) ? 0xff : 0;

            for (j = sizeof(size_t) - 1; j >= 0; j--)
            {
                if (((value >> (j << 3)) & 0xff) != sign)
                {
                    break;
                }
            }
            prefix |= sign ? 0x40 : 0;
            prefix |= j + 1;
            compressed[i++] = (unsigned char)prefix;

            for (; j >= 0; j--)
            {
                compressed[i++] = (unsigned char)(value & 0xff);
                value >>= 8;
            }

            lbridx = lbridx ? lbridx - 1 : vtss_lbr_no - 1;
        }
        /// save the resuling stack record
        if (i == VTSS_DYNSIZE_SCRATCH)
        {
            /// stack buffer overflowed
            strcat(stk->dbgmsg, "No room for LBR stacks");
            vtss_record_debug_info(trnd, stk->dbgmsg, 0);
            return -EFAULT;
        }
        else
        {

#ifdef VTSS_USE_UEC

            clrstk_trace_record_t stkrec;

            /// save current alt. stack in UEC: [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
            ///                                 ...[sampled address - 8b][systrace{sts}]
            ///                                                          [length - 2b][type - 2b]...
            stkrec.flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
            stkrec.residx = tid;
            stkrec.cpuidx = cpu;
            stkrec.cputsc = vtss_time_cpu();
            stkrec.execaddr = (unsigned long long)stk->user_ip.szt;

            stkrec.size = sizeof(stkrec.size) + sizeof(stkrec.type) + sizeof(stkrec.merge_node) + (unsigned short)i;
            stkrec.type = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
            stkrec.merge_node = 0xffffffff;

            if (vtss_transport_record_write(trnd, &stkrec, sizeof(stkrec), compressed, i, is_safe))
            {
                TRACE("STACK_record_write() FAIL");
                rc = -EFAULT;
            }

#else  // VTSS_USE_UEC

            void* entry;
            clrstk_trace_record_t* stkrec = (clrstk_trace_record_t*)vtss_transport_record_reserve(trnd, &entry, sizeof(clrstk_trace_record_t) + i);

            if (likely(stkrec))
            {
                /// save current alt. stack in UEC: [flagword - 4b][residx][cpuidx - 4b][tsc - 8b]
                ///                                 ...[sampled address - 8b][systrace{sts}]
                ///                                                          [length - 2b][type - 2b]...
                stkrec->flagword = UEC_LEAF1 | UECL1_VRESIDX | UECL1_CPUIDX | UECL1_CPUTSC | UECL1_EXECADDR | UECL1_SYSTRACE;
                stkrec->residx   = tid;
                stkrec->cpuidx   = cpu;
                stkrec->cputsc   = vtss_time_cpu();
                stkrec->execaddr = (unsigned long long)stk->user_ip.szt;

                stkrec->size = sizeof(stkrec->size) + sizeof(stkrec->type) + sizeof(stkrec->merge_node) + (unsigned short)i;
                stkrec->type = (sizeof(void*) == 8) ? UECSYSTRACE_CLEAR_STACK64 : UECSYSTRACE_CLEAR_STACK32;
                stkrec->merge_node = 0xffffffff;
                memcpy((char*)stkrec + sizeof(clrstk_trace_record_t), stk->compressed, i);
                rc = vtss_transport_record_commit(trnd, entry, is_safe);
            }
            else
            {
                TRACE("STACK_record_write() FAIL");
                rc = -EFAULT;
            }

#endif //  VTSS_USE_UEC

        }
    }
    return rc;
}

/* start LBR collection on the processor */
void vtss_lbr_enable(lbr_control_t* lbrctl)
{
    unsigned long long msr_val;

    if (hardcfg.family == VTSS_FAM_P6 && vtss_lbr_no) {
        if (vtss_lbr_msr_sel) {
            wrmsrl(vtss_lbr_msr_sel, 0ULL);
        }
        rdmsrl(DEBUGCTL_MSR, msr_val);

        msr_val |= (hardcfg.model == VTSS_CPU_HSW || hardcfg.model == VTSS_CPU_HSW_ULT) ? LBR_ENABLE_MASK_HSW : LBR_ENABLE_MASK_P6;

        wrmsrl(DEBUGCTL_MSR, 0);

        if (hardcfg.family == VTSS_FAM_P6 &&
            (hardcfg.model == VTSS_CPU_HSW || hardcfg.model == VTSS_CPU_HSW_ULT ||
             hardcfg.model == VTSS_CPU_BDW || hardcfg.model == VTSS_CPU_BDW_GT3 ||
             hardcfg.model == VTSS_CPU_BDW_XD || hardcfg.model == VTSS_CPU_BDW_X ||
             hardcfg.model == VTSS_CPU_SKL_M || hardcfg.model == VTSS_CPU_SKL || hardcfg.model == VTSS_CPU_SKL_X ||
             hardcfg.model == VTSS_CPU_KBL || hardcfg.model == VTSS_CPU_KBL_M ))
        {
            /// restore LBR stack
            int i, j;

            for (i = 0, j = 0; i < vtss_lbr_no; i++, j += 2)
            {
                /// TODO: temporarily disabled until arch resolves LBR restoration
                if (hardcfg.model == VTSS_CPU_SKL_M || hardcfg.model == VTSS_CPU_SKL || hardcfg.model == VTSS_CPU_SKL_X ||
                   hardcfg.model == VTSS_CPU_KBL || hardcfg.model == VTSS_CPU_KBL_M)
                {
                    wrmsrl(vtss_lbr_msr_from + i, lbrctl->lbrstk[j + 0]);
                    wrmsrl(vtss_lbr_msr_to + i, lbrctl->lbrstk[j + 1]);
                }
            }
            wrmsrl(vtss_lbr_msr_tos, lbrctl->lbrtos);

            /// enable LBR call stack
            wrmsrl(vtss_lbr_msr_sel, LBR_SELECT_MASK_HSW);
        }
        wrmsrl(DEBUGCTL_MSR, msr_val);
    }
}

/* stop LBR collection on the processor */
void vtss_lbr_disable(void)
{
    unsigned long long msr_val;

    if (hardcfg.family == VTSS_FAM_P6) {
        rdmsrl(DEBUGCTL_MSR, msr_val);
        msr_val &= (hardcfg.model == VTSS_CPU_HSW || hardcfg.model == VTSS_CPU_HSW_ULT) ? ~LBR_ENABLE_MASK_HSW : ~LBR_ENABLE_MASK_P6;
        wrmsrl(DEBUGCTL_MSR, msr_val);
    }
}

/* stop LBR collection on the processor and save LBR stack */
void vtss_lbr_disable_save(lbr_control_t* lbrctl)
{
    unsigned long long msr_val;

    if (hardcfg.family == VTSS_FAM_P6) {
        rdmsrl(DEBUGCTL_MSR, msr_val);
        msr_val &= (hardcfg.model == VTSS_CPU_HSW || hardcfg.model == VTSS_CPU_HSW_ULT) ? ~LBR_ENABLE_MASK_HSW : ~LBR_ENABLE_MASK_P6;
        wrmsrl(DEBUGCTL_MSR, msr_val);
    }
    /// save LBR stack
    if (hardcfg.family == VTSS_FAM_P6 &&
        (hardcfg.model == VTSS_CPU_HSW || hardcfg.model == VTSS_CPU_HSW_ULT ||
         hardcfg.model == VTSS_CPU_BDW || hardcfg.model == VTSS_CPU_BDW_GT3 ||
         hardcfg.model == VTSS_CPU_BDW_XD || hardcfg.model == VTSS_CPU_BDW_X ||
         hardcfg.model == VTSS_CPU_SKL_M || hardcfg.model == VTSS_CPU_SKL || hardcfg.model == VTSS_CPU_SKL_X ||
         hardcfg.model == VTSS_CPU_KBL || hardcfg.model == VTSS_CPU_KBL_M ))
    {
        int i, j;

        for (i = 0, j = 0; i < vtss_lbr_no; i++, j += 2)
        {
            lbrctl->lbrstk[j + 0] = read_msr(vtss_lbr_msr_from + i);
            lbrctl->lbrstk[j + 1] = read_msr(vtss_lbr_msr_to + i);
        }

        lbrctl->lbrtos = read_msr(vtss_lbr_msr_tos);
    }
}

/* initialize the architectural LBR parameters */
int vtss_lbr_init(void)
{
    /* zero the LBR configuration by default */
    vtss_lbr_no       = 0;
    vtss_lbr_msr_ctl  = 0;
    vtss_lbr_msr_from = 0;
    vtss_lbr_msr_to   = 0;
    vtss_lbr_msr_tos  = 0;
    vtss_lbr_msr_sel  = 0;

    /* test the current architecture */
    if (hardcfg.family == VTSS_FAM_P6) {
        switch (hardcfg.model) {
            /* SKL/SKX/KBL */
        case VTSS_CPU_SKL_M:
        case VTSS_CPU_SKL:
        case VTSS_CPU_SKL_X:
        case VTSS_CPU_KBL:
        case VTSS_CPU_KBL_M:
            vtss_lbr_no       = 32;
            vtss_lbr_msr_from = 0x0680;
            vtss_lbr_msr_to   = 0x06c0;
            vtss_lbr_msr_tos  = 0x01c9;
            vtss_lbr_msr_sel  = 0x01c8;
            break;
        /* NHM/SNB/IVB/HSW/BDW */
        case VTSS_CPU_NHM_EP:
        case VTSS_CPU_NHM:
        case VTSS_CPU_NHM_G:
        case VTSS_CPU_NHM_EX:
        case VTSS_CPU_WMR:
        case VTSS_CPU_WMR_EP:
        case VTSS_CPU_SNB:
        case VTSS_CPU_SNB_X:
        case VTSS_CPU_IVB:
        case VTSS_CPU_HSW:
        case VTSS_CPU_HSW_ULT:
            vtss_lbr_no       = 16;
            vtss_lbr_msr_from = 0x0680;
            vtss_lbr_msr_to   = 0x06c0;
            vtss_lbr_msr_tos  = 0x01c9;
            vtss_lbr_msr_sel  = 0x01c8;
            break;
        /* Atoms */
        case VTSS_CPU_ATOM_BNL:
        case VTSS_CPU_ATOM_SLW_T:
        case VTSS_CPU_ATOM_SLW:
            vtss_lbr_no       = 8;
            vtss_lbr_msr_from = 0x40;
            vtss_lbr_msr_to   = 0x60;
            vtss_lbr_msr_tos  = 0x01c9;
            break;
        /* Core2s */
        case VTSS_CPU_MRM:
        case VTSS_CPU_PNR:
        case VTSS_CPU_DNG:
            vtss_lbr_no       = 4;
            vtss_lbr_msr_from = 0x40;
            vtss_lbr_msr_to   = 0x60;
            vtss_lbr_msr_tos  = 0x01c9;
            break;
        default:
            if (hardcfg.model >= 0x02 && hardcfg.model < VTSS_CPU_MRM) {
                vtss_lbr_no       = 8;
                vtss_lbr_msr_ctl  = 0x40;
                vtss_lbr_msr_tos  = 0x01c9;
            }
            break;
        }
    }
    TRACE("no=%d, ctl=0x%X, from=0x%X, to=0x%X, tos=0x%X",
          vtss_lbr_no, vtss_lbr_msr_ctl, vtss_lbr_msr_from, vtss_lbr_msr_to, vtss_lbr_msr_tos);
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_LASTBR)
        REPORT("LBR: stack size: %d", vtss_lbr_no);
    return 0;
}

static void vtss_lbr_on_each_cpu_func(void* ctx)
{
    vtss_lbr_disable();
}

void vtss_lbr_fini(void)
{
    on_each_cpu(vtss_lbr_on_each_cpu_func, NULL, SMP_CALL_FUNCTION_ARGS);
}

/*
  Copyright (C) 2018-2019 Intel Corporation.  All Rights Reserved.

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
#ifndef _VTSS_DEBUG_H_
#define _VTSS_DEBUG_H_

#include <linux/kernel.h>

#ifdef VTSS_DEBUG_TRACE
extern int vtss_check_trace(const char* func_name, int* flag);
#define TRACE(FMT, ...) do {   \
    static int trace_flag = 0; \
    if (unlikely(!trace_flag))  trace_flag = vtss_check_trace(__FUNCTION__, &trace_flag); \
    if (unlikely(trace_flag>0)) printk(KERN_DEBUG "%s(%d): [cpu%d]: "FMT"\n", __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__); \
  } while (0)
#else
#define TRACE(FMT, ...) /* empty */
#endif
#define ERROR(FMT, ...) do { printk(KERN_ERR "vtsspp: "FMT"\n", ##__VA_ARGS__); } while (0)
#define WARNING(FMT, ...) do { printk(KERN_WARNING "vtsspp: "FMT"\n", ##__VA_ARGS__); } while (0)
#define REPORT(FMT, ...)  do { printk(KERN_NOTICE "vtsspp: "FMT"\n", ##__VA_ARGS__); } while (0)
#define INFO(FMT, ...)  do { printk(KERN_INFO "%s(%d): [cpu%d]: "FMT"\n", __FUNCTION__, __LINE__, raw_smp_processor_id(), ##__VA_ARGS__); } while (0)

#define DEBUG_COLLECTOR TRACE
#define DEBUG_CPUEVT TRACE
#define DEBUG_PROCFS TRACE
#define DEBUG_TR TRACE  /* transport */
#define DEBUG_MP TRACE  /* memory pool */
#define DEBUG_TP TRACE  /* tracepoints */
#define DEBUG_KPROBE TRACE

#ifdef VTSS_DEBUG_STACK
#define VTSS_MIN_STACK_SPACE 1024
#endif

#ifdef VTSS_DEBUG_PROFILE
struct vtss_profile {
    cycles_t cnt_stk;
    cycles_t clk_stk;
    cycles_t cnt_ctx;
    cycles_t clk_ctx;
    cycles_t cnt_pmi;
    cycles_t clk_pmi;
    cycles_t cnt_pmu;
    cycles_t clk_pmu;
    cycles_t cnt_sys;
    cycles_t clk_sys;
    cycles_t cnt_bts;
    cycles_t clk_bts;
    cycles_t cnt_vma;
    cycles_t clk_vma;
    cycles_t cnt_pgp;
    cycles_t clk_pgp;
    cycles_t cnt_cpy;
    cycles_t clk_cpy;
    cycles_t cnt_vld;
    cycles_t clk_vld;
    cycles_t cnt_unw;
    cycles_t clk_unw;
};

extern struct vtss_profile vtss_profile;

#define VTSS_DEFINE_PROFILE_STRUCT()\
    struct vtss_profile vtss_profile

#define VTSS_PROFILE_RESET() \
    memset(&vtss_profile, 0, sizeof(struct vtss_profile))

#define VTSS_PROFILE_BEGIN(name) do { \
    cycles_t start_time_##name = get_cycles()

#define VTSS_PROFILE_END(name) \
    vtss_profile.cnt_##name++; \
    vtss_profile.clk_##name += get_cycles() - start_time_##name; \
  } while (0)

#define VTSS_PROFILE(name, expr) \
    VTSS_PROFILE_BEGIN(name); \
    (expr); \
    VTSS_PROFILE_END(name);

#define VTSS_PROFILE_PRINT(func, ...) do { \
    func(__VA_ARGS__ "#ctx=%15lld n=%9lld\n", \
        vtss_profile.clk_ctx, vtss_profile.cnt_ctx); \
    func(__VA_ARGS__ "#pmi=%15lld n=%9lld\n", \
        vtss_profile.clk_pmi, vtss_profile.cnt_pmi/2); \
    func(__VA_ARGS__ "*pmu=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_pmu, vtss_profile.cnt_pmu, \
        (vtss_profile.clk_pmu*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))/100, \
        (vtss_profile.clk_pmu*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))%100); \
    func(__VA_ARGS__ "*sys=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_sys, vtss_profile.cnt_sys, \
        (vtss_profile.clk_sys*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))/100, \
        (vtss_profile.clk_sys*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))%100); \
    func(__VA_ARGS__ "*bts=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_bts, vtss_profile.cnt_bts, \
        (vtss_profile.clk_bts*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))/100, \
        (vtss_profile.clk_bts*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))%100); \
    func(__VA_ARGS__ "*stk=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_stk, vtss_profile.cnt_stk, \
        (vtss_profile.clk_stk*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))/100, \
        (vtss_profile.clk_stk*10000/(vtss_profile.clk_ctx+vtss_profile.clk_pmi+1))%100); \
    func(__VA_ARGS__ ".unw=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_unw, vtss_profile.cnt_unw, \
        (vtss_profile.clk_unw*10000/(vtss_profile.clk_stk+1))/100, \
        (vtss_profile.clk_unw*10000/(vtss_profile.clk_stk+1))%100); \
    func(__VA_ARGS__ ".vld=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_vld, vtss_profile.cnt_vld, \
        (vtss_profile.clk_vld*10000/(vtss_profile.clk_unw+1))/100, \
        (vtss_profile.clk_vld*10000/(vtss_profile.clk_unw+1))%100); \
    func(__VA_ARGS__ ".vma=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_vma, vtss_profile.cnt_vma, \
        (vtss_profile.clk_vma*10000/(vtss_profile.clk_unw+1))/100, \
        (vtss_profile.clk_vma*10000/(vtss_profile.clk_unw+1))%100); \
    func(__VA_ARGS__ ".cpy=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_cpy, vtss_profile.cnt_cpy, \
        (vtss_profile.clk_cpy*10000/(vtss_profile.clk_vma+1))/100, \
        (vtss_profile.clk_cpy*10000/(vtss_profile.clk_vma+1))%100); \
    func(__VA_ARGS__ ".pgp=%15lld n=%9lld (%.2lld.%02lld%%)\n", \
        vtss_profile.clk_pgp, vtss_profile.cnt_pgp, \
        (vtss_profile.clk_pgp*10000/(vtss_profile.clk_vma+1))/100, \
        (vtss_profile.clk_pgp*10000/(vtss_profile.clk_vma+1))%100); \
  } while (0)

#else
#define VTSS_DEFINE_PROFILE_STRUCT()
#define VTSS_PROFILE_RESET()
#define VTSS_PROFILE_BEGIN(name) do {
#define VTSS_PROFILE_END(name) } while (0)
#define VTSS_PROFILE(name, expr) (expr)
#define VTSS_PROFILE_PRINT(func, ...)
#endif

#endif

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
#ifndef _UNWIND_H_
#define _UNWIND_H_

#include <linux/compiler.h>     /* for inline */
#include <linux/types.h>        /* for size_t */
#include <linux/stddef.h>       /* for NULL   */
#include <linux/spinlock.h>

#include "user_vm.h"
#include "globals.h"
#include "utils.h"

/**
// Constants and Macros
*/
#define MAX_USER_ADDRESS32  0x7ffeffff
#define MAX_USER_ADDRESS3G  0xc0000000
#define MIN_MODULE_ADDRESS  0x001a0000
#define CRITICAL_ADDRESS    0x10000000
#define MAX_INSTR_SIZE 7

#define IP_SEARCH_RANGE     0x08
#define FUN_SEARCH_RANGE    0x1000

#define MIN_SYSTEM_MODULE   0x77800000
#define MAX_SYSTEM_MODULE   0x7ffeffff

#define CALLND_OPCODE 0xe8
#define CALLNI_OPCODE 0xff
#define CALLNI_OPEXT  0x10      /// xx010xxx
#define CALLNI_OPMASK 0x38      /// 00111xxx

#define VTSS_STACK_CACHE_SIZE PAGE_SIZE
#define VTSS_STACK_READ_SIZE PAGE_SIZE
#define VTSS_STACK_READ_MASK (0-VTSS_STACK_READ_SIZE)
/**
// Data Types
*/

/// stack pointer (to walk by different strides)
typedef union
{
    char *chp;
    void *vdp;
    void **vpp;
    size_t *szp;
    unsigned *uip;
    size_t szt;

} stkptr_t;

/// stack map element to map SP to either FP or IP
typedef struct
{
    stkptr_t sp;

    union
    {
        size_t fp;
        size_t ip;
        stkptr_t value;
    };

} stkmap_t;

/// general stack unwinding control structure
typedef struct _stack_control_t
{
    /// buffer properties
    char *buffer;               /// buffer allocated for all stack unwinding operations
    int size;                   /// the buffer's size

    /// stack map properties
    stkmap_t *stkmap_end;       /// end of stack map (the unwinding starts from here)
    stkmap_t *stkmap_common;    /// common element on the stack map
    stkmap_t *stkmap_start;     /// the beginning of the map (compression starts here)

    /// dynamic return address detection properties
    stkptr_t value;
    stkptr_t cm_low;            /// low address of the current module
    stkptr_t cm_high;           /// high address of the current module

    /// output compression properties
    unsigned char *compressed;  /// compressed data buffer

    /// sample properties
    stkptr_t user_ip;           /// IP for the current sample
    stkptr_t user_sp;           /// SP for the current sample
    stkptr_t bp;                /// stack base for the current sample
    stkptr_t user_fp;           /// frame pointer for the current sample
    int wow64;                  /// WoW64 process flag
    int huge;                   /// stack in hugetlb area
#ifdef VTSS_CONFIG_REALTIME
    raw_spinlock_t spin_lock;   /// spin lock protection
#else
    spinlock_t spin_lock;       /// spin lock protection
#endif
    user_vm_accessor_t* acc;    /// user vm accessor
    char dbgmsg[192];

    /// kernel clean stack
    char *kernel_callchain;
    int kernel_callchain_size;
    int kernel_callchain_pos;
    stkptr_t fp;                /// frame pointer for the current sample
    stkptr_t ip;                /// IP for the current sample
    stkptr_t sp;                /// SP for the current sample
    /// user clean stack
    char *user_callchain;
    int user_callchain_size;
    int user_callchain_pos;

    char value_cache[VTSS_STACK_CACHE_SIZE];

} stack_control_t;


/**
// Function Declarations
*/
int vtss_init_stack(stack_control_t* stk);
void vtss_destroy_stack(stack_control_t* stk);
int vtss_realloc_stack(stack_control_t* stk);
void vtss_clear_stack(stack_control_t* stk);
int vtss_unwind_stack_fwd(stack_control_t* stk);
int vtss_compress_stack(stack_control_t* stk);

/// check if the stack map increment is zero
static inline int vtss_is_full_stack(stack_control_t* stk)
{
    return stk->stkmap_common == stk->stkmap_end;
}

static inline void vtss_lock_stack(stack_control_t* stk)
{
    vtss_spin_lock(&stk->spin_lock);
}

static inline int vtss_trylock_stack(stack_control_t* stk)
{
    if (!stk->acc) return 0;
    return vtss_spin_trylock(&stk->spin_lock);
}

static inline void vtss_unlock_stack(stack_control_t* stk)
{
    vtss_spin_unlock(&stk->spin_lock);
}

#endif /* _UNWIND_H_ */

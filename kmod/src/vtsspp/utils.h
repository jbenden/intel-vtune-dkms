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
#ifndef _VTSS_UTILS_H_
#define _VTSS_UTILS_H_

#include "config.h"

unsigned long vtss_kallsyms_lookup_name(const char *name);

#include <linux/kprobes.h>
int vtss_register_kprobe(struct kprobe *kp, const char *name);
int vtss_unregister_kprobe(struct kprobe *kp);
int vtss_register_kretprobe(struct kretprobe *rp, const char *name);
int vtss_unregister_kretprobe(struct kretprobe *rp);
#ifdef VTSS_AUTOCONF_JPROBE
int vtss_register_jprobe(struct jprobe *jp, const char *name);
int vtss_unregister_jprobe(struct jprobe *jp);
#endif

struct task_struct* vtss_find_task_by_tid(pid_t tid);

#pragma pack(push, 1)
struct vtss_work
{
    struct work_struct work; /* !!! SHOULD BE THE FIRST !!! */
    char data[0];            /*     placeholder for data    */
};
#pragma pack(pop)

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
#define VTSS_WORK_STRUCT struct work_struct
#else
#define VTSS_WORK_STRUCT void
#endif

typedef void (vtss_work_func_t) (VTSS_WORK_STRUCT *work);
int vtss_queue_work(int cpu, vtss_work_func_t* func, void* data, size_t size);

#define vtss_get_task_struct(task) get_task_struct(task)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
int vtss_put_task_struct_init(void);
void vtss_put_task_struct(struct task_struct *task);
#else
#define vtss_put_task_struct_init() 0
#define vtss_put_task_struct(task) put_task_struct(task)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
char *vtss_get_task_comm(char *taskname, struct task_struct *task);
#else
#define vtss_get_task_comm(name, task) get_task_comm(name, task)
#endif

#ifdef CONFIG_X86_64
#define VTSS_KOFFSET ((unsigned long)__START_KERNEL_map)
#define VTSS_MAX_USER_SPACE 0x7fffffffffff
#else
#define VTSS_KOFFSET ((unsigned long)PAGE_OFFSET)
#define VTSS_MAX_USER_SPACE 0x7fffffff
#endif

#ifndef KERNEL_IMAGE_SIZE
#define KERNEL_IMAGE_SIZE (512 * 1024 * 1024)
#endif

#define VTSS_KSTART (VTSS_KOFFSET + ((CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & ~(CONFIG_PHYSICAL_ALIGN - 1)))
#define VTSS_KSIZE  ((unsigned long)KERNEL_IMAGE_SIZE - ((CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & ~(CONFIG_PHYSICAL_ALIGN - 1)) - 1)

void vtss_get_kstart(unsigned long *addr, unsigned long *size);

#ifdef VTSS_CONFIG_KPTI
int vtss_cea_init(void);
void vtss_cea_update(void *cea, void *addr, size_t size, pgprot_t prot);
void vtss_cea_clear(void *cea, size_t size);
void *vtss_cea_alloc_pages(size_t size, gfp_t flags, int cpu);
void vtss_cea_free_pages(const void *buffer, size_t size);
#endif

#ifdef VTSS_CONFIG_KAISER
int vtss_kaiser_init(void);
void *vtss_kaiser_alloc_pages(size_t size, gfp_t flags, int cpu);
void vtss_kaiser_free_pages(const void *buffer, size_t size);
#endif

#ifdef VTSS_CONFIG_REALTIME
#define VTSS_DEFINE_SPINLOCK DEFINE_RAW_SPINLOCK
#define vtss_spin_lock_init(lock)                raw_spin_lock_init(lock)
#define vtss_spin_trylock(lock)                  raw_spin_trylock(lock)
#define vtss_spin_lock(lock)                     raw_spin_lock(lock)
#define vtss_spin_unlock(lock)                   raw_spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)      raw_spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)   raw_spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) raw_spin_unlock_irqrestore(lock, flags)
#else
#define VTSS_DEFINE_SPINLOCK DEFINE_SPINLOCK
#define vtss_spin_lock_init(lock)                spin_lock_init(lock)
#define vtss_spin_trylock(lock)                  spin_trylock(lock)
#define vtss_spin_lock(lock)                     spin_lock(lock)
#define vtss_spin_unlock(lock)                   spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)      spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)   spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) spin_unlock_irqrestore(lock, flags)
#endif

#ifdef VTSS_CONFIG_REALTIME
static inline int vtss_spin_lock_irqsave_timeout(raw_spinlock_t *lock, unsigned long flags, int times)
#else
static inline int vtss_spin_lock_irqsave_timeout(spinlock_t *lock, unsigned long flags, int times)
#endif
{
    int rc = 0;
    int cnt = 0;

    while (!(rc = vtss_spin_trylock_irqsave(lock, flags))) {
        if (++cnt >= (times)) {
            TRACE("cannot acquire lock");
            break;
        }
    }
    return rc;
}

#include <linux/slab.h>
#ifdef VTSS_CONFIG_INTERNAL_MEMORY_POOL
#include "memory_pool.h"
#define vtss_get_free_pages(gfp_mask, order) vtss_get_free_pages_internal(gfp_mask, order)
#define vtss_free_pages(addr, order)         vtss_free_pages_internal(addr, order)
#define vtss_get_free_page(gfp_mask)         vtss_get_free_page_internal(gfp_mask)
#define vtss_free_page(addr)                 vtss_free_page_internal(addr)
#define vtss_kmalloc(size, gfp_mask)         vtss_kmalloc_internal(size, gfp_mask)
#define vtss_kfree(item)                     vtss_kfree_internal(item)
#else
#define vtss_get_free_pages(gfp_mask, order) __get_free_pages((gfp_mask) | ((gfp_mask) == GFP_NOWAIT ? __GFP_NORETRY : 0) | __GFP_NOWARN, order)
#define vtss_free_pages(addr, order)         free_pages(addr, order)
#define vtss_get_free_page(gfp_mask)         __get_free_page((gfp_mask) | ((gfp_mask) == GFP_NOWAIT ? __GFP_NORETRY : 0) | __GFP_NOWARN)
#define vtss_free_page(addr)                 free_page(addr)
#define vtss_kmalloc(size, gfp_mask)         kmalloc(size, gfp_mask)
#define vtss_kfree(item)                     kfree(item)
#endif

#define VTSS_TO_STR_AUX(x) #x
#define VTSS_TO_STR(x) VTSS_TO_STR_AUX(x)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#define vtss_user_mode(regs) user_mode(regs)
#else
#define vtss_user_mode(regs) user_mode_vm(regs)
#endif

#ifdef CONFIG_X86_32
#define VTSS_GET_CURRENT_BP(bp) asm("movl %%ebp, %0":"=r"(bp):)
#else
#define VTSS_GET_CURRENT_BP(bp) asm("movq %%rbp, %0":"=r"(bp):)
#endif

#ifdef VTSS_AUTOCONF_X86_UNIREGS
#define REG(name, regs) ((regs)->name)
#else
#if defined(CONFIG_X86_32)
#define REG(name, regs) ((regs)->e##name)
#elif defined(CONFIG_X86_64)
#define REG(name, regs) ((regs)->r##name)
#endif
#endif

#ifdef VTSS_AUTOCONF_DPATH_PATH
#include <linux/path.h>
#define VTSS_DPATH(vm_file, name, maxlen) d_path(&((vm_file)->f_path), (name), (maxlen))
#else
#define VTSS_DPATH(vm_file, name, maxlen) d_path((vm_file)->f_path.dentry, (vm_file)->f_vfsmnt, (name), (maxlen))
#endif

#ifdef VTSS_AUTOCONF_USER_COPY_WITHOUT_CHECK
#define vtss_copy_from_user _copy_from_user
#else
#define vtss_copy_from_user copy_from_user
#endif

#ifndef preempt_enable_no_resched
#define preempt_enable_no_resched() preempt_enable()
#endif

#endif

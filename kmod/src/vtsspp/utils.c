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
#include "config.h"
#include "vtsserr.h"
#include "utils.h"

#include <linux/kallsyms.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#include <asm-generic/io.h>
#endif

#ifdef CONFIG_KALLSYMS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
unsigned long vtss_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#else
struct vtss_kallsyms_data
{
    const char *name;
    unsigned long ptr;
};

int vtss_kallsyms_lookup_callback(void* data, const char *name, struct module *mod, unsigned long addr)
{
    struct vtss_kallsyms_data *kdata = data;

    if (name) {
        if (kdata) {
            if (!strcmp(name, kdata->name)) {
                kdata->ptr = addr;
                return 1;
            }
        }
    }
    return 0;
}

unsigned long vtss_kallsyms_lookup_name(const char *name)
{
    struct vtss_kallsyms_data kdata;

    kdata.name = name;
    kdata.ptr = 0;
    kallsyms_on_each_symbol(vtss_kallsyms_lookup_callback, (void*)&kdata);
    TRACE("found symbol: %s=0x%lx", name, kdata.ptr);
    return kdata.ptr;
}
#endif
#else
unsigned long vtss_kallsyms_lookup_name(const char *name)
{
    return NULL;
}
#endif

#include <linux/kprobes.h>

static int vtss_init_kprobe(struct kprobe *kp, const char *name)
{
    kp->addr = NULL,
#ifdef VTSS_AUTOCONF_KPROBE_SYMBOL_NAME
    kp->symbol_name = name;
#else
    kp->addr = (kprobe_opcode_t *)vtss_kallsyms_lookup_name(name);
    if (!kp->addr) {
        DEBUG_KPROBE("unable to find symbol '%s'", name);
        return -1;
    }
#endif
#ifdef VTSS_AUTOCONF_KPROBE_FLAGS
    kp->flags = 0;
#endif
    return 0;
}

int vtss_register_kprobe(struct kprobe *kp, const char *name)
{
    int rc = 0;

    rc = vtss_init_kprobe(kp, name);
    if (rc) return rc;

    if (!kp->pre_handler) DEBUG_KPROBE("pre_handler field is empty");
    kp->fault_handler = NULL;

    rc = register_kprobe(kp);
    if (rc) {
        DEBUG_KPROBE("unable to register kprobe '%s'", name);
        kp->addr = NULL;
    }
    else DEBUG_KPROBE("registered '%s' probe", name);

    return rc;
}

int vtss_unregister_kprobe(struct kprobe *kp)
{
    if (kp->addr) {
        unregister_kprobe(kp);
        kp->addr = NULL;
#ifdef VTSS_AUTOCONF_KPROBE_SYMBOL_NAME
        DEBUG_KPROBE("unregistered '%s' probe", kp->symbol_name);
#endif
    }
    return 0;
}

int vtss_register_kretprobe(struct kretprobe *rp, const char *name)
{
    int rc = 0;

    rc = vtss_init_kprobe(&rp->kp, name);
    if (rc) return rc;

    if (!rp->entry_handler) DEBUG_KPROBE("entry_handler field is empty");
    if (!rp->handler) DEBUG_KPROBE("handler field is empty");
    rp->maxactive = 16; /* probe up to 16 instances concurrently */

    rc = register_kretprobe(rp);
    if (rc) {
        DEBUG_KPROBE("unable to register kretprobe '%s'", name);
        rp->kp.addr = NULL;
    }
    else DEBUG_KPROBE("registered '%s' probe", name);

    return rc;
}

int vtss_unregister_kretprobe(struct kretprobe *rp)
{
    if (rp->kp.addr) {
        unregister_kretprobe(rp);
        rp->kp.addr = NULL;
#ifdef VTSS_AUTOCONF_KPROBE_SYMBOL_NAME
        DEBUG_KPROBE("unregistered '%s' probe", rp->kp.symbol_name);
#endif
    }
    return 0;
}

#ifdef VTSS_AUTOCONF_JPROBE
int vtss_register_jprobe(struct jprobe *jp, const char *name)
{
    int rc = 0;

    rc = vtss_init_kprobe(&jp->kp, name);
    if (rc) return rc;

    if (!jp->entry) DEBUG_KPROBE("entry field is empty");

    rc = register_jprobe(jp);
    if (rc) {
        DEBUG_KPROBE("unable to register jprobe '%s'", name);
        jp->kp.addr = NULL;
    }
    else DEBUG_KPROBE("registered '%s' probe", name);

    return rc;
}

int vtss_unregister_jprobe(struct jprobe *jp)
{
    if (jp->kp.addr) {
        unregister_jprobe(jp);
        jp->kp.addr = NULL;
    }
    return 0;
}
#endif

struct task_struct* vtss_find_task_by_tid(pid_t tid)
{
    struct task_struct *task = NULL;
    struct pid *p_pid = NULL;

    p_pid = find_get_pid(tid);
    if (p_pid) {
        rcu_read_lock();
        task = pid_task(p_pid, PIDTYPE_PID);
        rcu_read_unlock();
        put_pid(p_pid);
    }
    return task;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static void (*vtss__put_task_struct)(struct task_struct *tsk) = NULL;

int vtss_put_task_struct_init(void)
{
    if (vtss__put_task_struct == NULL) {
        vtss__put_task_struct = (void*)vtss_kallsyms_lookup_name("__put_task_struct");
        if (vtss__put_task_struct == NULL) {
            ERROR("Cannot find '__put_task_struct' symbol");
            return -1;
        }
    }
    return 0;
}

void vtss_put_task_struct(struct task_struct *task)
{
    if (atomic_dec_and_test(&task->usage))
        vtss__put_task_struct(task);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
char *vtss_get_task_comm(char *taskname, struct task_struct *task)
{
    task_lock(task);
    strncpy(taskname, task->comm, VTSS_TASKNAME_SIZE-1);
    taskname[VTSS_TASKNAME_SIZE-1] = '\0';
    task_unlock(task);
    return taskname;
}
#endif

int vtss_queue_work(int cpu, vtss_work_func_t* func, void* data, size_t size)
{
    struct vtss_work* my_work = 0;

    my_work = (struct vtss_work*)vtss_kmalloc(sizeof(struct vtss_work)+size, GFP_ATOMIC);

    if (my_work != NULL) {
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
        INIT_WORK((struct work_struct*)my_work, func);
#else
        INIT_WORK((struct work_struct*)my_work, func, my_work);
#endif
        if (data != NULL && size > 0)
            memcpy(&my_work->data, data, size);

#ifdef VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ

#ifdef VTSS_CONFIG_REALTIME
        queue_work(system_unbound_wq, (struct work_struct*)my_work);
#else
        if (cpu < 0) {
            queue_work(system_unbound_wq, (struct work_struct*)my_work);
        } else {
            queue_work_on(cpu, system_unbound_wq, (struct work_struct*)my_work);
        }
#endif /* VTSS_CONFIG_REALTIME */

#else  /* VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ */
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
        if (cpu < 0) {
            schedule_work((struct work_struct*)my_work);
        } else {
            schedule_work_on(cpu, (struct work_struct*)my_work);
        }
#else  /* VTSS_AUTOCONF_INIT_WORK_TWO_ARGS */
        /* Don't support queue work on cpu */
        schedule_work((struct work_struct*)my_work);
#endif /* VTSS_AUTOCONF_INIT_WORK_TWO_ARGS */
#endif /* VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ */
    } else {
        ERROR("No memory for work data");
        return -ENOMEM;
    }
    return 0;
}

void vtss_get_kstart(unsigned long *addr, unsigned long *size)
{
#ifdef CONFIG_RANDOMIZE_BASE
    unsigned long dyn_addr;
#endif
    *addr = VTSS_KSTART;
    *size = VTSS_KSIZE;
#ifdef CONFIG_RANDOMIZE_BASE
    /* fixup kernel start address of KASLR kernels */
    dyn_addr = vtss_kallsyms_lookup_name("_text") & ~(PAGE_SIZE - 1);
    if (dyn_addr > *addr) {
        TRACE("vmlinux: addr=0x%lx, dyn_addr=0x%lx", *addr, dyn_addr);
        *size -= (dyn_addr - *addr);
        *addr = dyn_addr;
    }
    else if (!dyn_addr) {
        dyn_addr = vtss_kallsyms_lookup_name("_stext") & ~(PAGE_SIZE - 1);
        if (dyn_addr > *addr) {
            TRACE("vmlinux: addr=0x%lx, stext dyn_addr=0x%lx", *addr, dyn_addr);
            *size -= (dyn_addr - *addr);
            *addr = dyn_addr;
        }
    }
#endif
}

#ifdef VTSS_CONFIG_KPTI
#include <asm/tlbflush.h>
#include <linux/kallsyms.h>

static void (*vtss_cea_set_pte)(void *cea_vaddr, phys_addr_t pa, pgprot_t flags) = NULL;
static void (*vtss_do_kernel_range_flush)(void *info) = NULL;

int vtss_cea_init(void)
{
    if (vtss_cea_set_pte == NULL) {
        vtss_cea_set_pte = (void*)vtss_kallsyms_lookup_name("cea_set_pte");
        if (vtss_cea_set_pte == NULL) {
            ERROR("Cannot find 'cea_set_pte' symbol");
            return VTSS_ERR_INTERNAL;
        }
    }
    if (vtss_do_kernel_range_flush == NULL) {
        vtss_do_kernel_range_flush = (void*)vtss_kallsyms_lookup_name("do_kernel_range_flush");
        if (vtss_do_kernel_range_flush == NULL) {
            ERROR("Cannot find 'do_kernel_range_flush' symbol");
            return VTSS_ERR_INTERNAL;
        }
    }
    REPORT("KPTI is enabled");
    return 0;
}

void vtss_cea_update(void *cea, void *addr, size_t size, pgprot_t prot)
{
    unsigned long start = (unsigned long)cea;
    struct flush_tlb_info info;
    phys_addr_t pa;
    size_t msz = 0;

    pa = virt_to_phys(addr);

    preempt_disable();
    for (; msz < size; msz += PAGE_SIZE, pa += PAGE_SIZE, cea += PAGE_SIZE)
        vtss_cea_set_pte(cea, pa, prot);

    info.start = start;
    info.end = start + size;
    vtss_do_kernel_range_flush(&info);
    preempt_enable();
}

void vtss_cea_clear(void *cea, size_t size)
{
    unsigned long start = (unsigned long)cea;
    struct flush_tlb_info info;
    size_t msz = 0;

    preempt_disable();
    for (; msz < size; msz += PAGE_SIZE, cea += PAGE_SIZE)
        vtss_cea_set_pte(cea, 0, PAGE_NONE);

    info.start = start;
    info.end = start + size;
    vtss_do_kernel_range_flush(&info);
    preempt_enable();
}

void *vtss_cea_alloc_pages(size_t size, gfp_t flags, int cpu)
{
    unsigned int order = get_order(size);
    int node = cpu_to_node(cpu);
    struct page *page;

    page = alloc_pages_node(node, flags | __GFP_ZERO, order);
    return page ? page_address(page) : NULL;
}

void vtss_cea_free_pages(const void *buffer, size_t size)
{
    if (buffer)
        free_pages((unsigned long)buffer, get_order(size));
}
#endif

#ifdef VTSS_CONFIG_KAISER
#include <linux/kaiser.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>

static int (*vtss_kaiser_add_mapping)(unsigned long addr, unsigned long size, pteval_t flags) = NULL;
static void (*vtss_kaiser_remove_mapping)(unsigned long start, unsigned long size) = NULL;
static int vtss_kaiser_enabled = 0;

int vtss_kaiser_init(void)
{
    int *kaiser_enabled_ptr = (int*)vtss_kallsyms_lookup_name("kaiser_enabled");
    if (kaiser_enabled_ptr) {
        vtss_kaiser_enabled = *kaiser_enabled_ptr;
        REPORT("KAISER is %s", vtss_kaiser_enabled ? "enabled" : "disabled");
    }
    else {
        vtss_kaiser_enabled = 1;
        REPORT("KAISER is auto");
    }
    if (vtss_kaiser_enabled) {
        if (vtss_kaiser_add_mapping == NULL) {
            vtss_kaiser_add_mapping = (void*)vtss_kallsyms_lookup_name("kaiser_add_mapping");
            if (vtss_kaiser_add_mapping == NULL) {
                ERROR("Cannot find 'kaiser_add_mapping' symbol");
                return VTSS_ERR_INTERNAL;
            }
        }
        if (vtss_kaiser_remove_mapping == NULL) {
            vtss_kaiser_remove_mapping = (void*)vtss_kallsyms_lookup_name("kaiser_remove_mapping");
            if (vtss_kaiser_remove_mapping == NULL) {
                ERROR("Cannot find 'kaiser_remove_mapping' symbol");
                return VTSS_ERR_INTERNAL;
            }
        }
    }
    return 0;
}

void *vtss_kaiser_alloc_pages(size_t size, gfp_t flags, int cpu)
{
    unsigned int order = get_order(size);
    int node = cpu_to_node(cpu);
    struct page *page;
    unsigned long addr;

    page = alloc_pages_node(node, flags | __GFP_ZERO, order);
    if (!page)
        return NULL;
    addr = (unsigned long)page_address(page);
    if (vtss_kaiser_enabled) {
        if (vtss_kaiser_add_mapping(addr, size, __PAGE_KERNEL | _PAGE_GLOBAL) < 0) {
            __free_pages(page, order);
            addr = 0;
        }
    }
    return (void *)addr;
}

void vtss_kaiser_free_pages(const void *buffer, size_t size)
{
    if (!buffer)
        return;
    if (vtss_kaiser_enabled) {
        vtss_kaiser_remove_mapping((unsigned long)buffer, size);
    }
    free_pages((unsigned long)buffer, get_order(size));
}
#endif


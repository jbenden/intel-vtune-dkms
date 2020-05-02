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

#ifndef VTSS_VMA_TIME_LIMIT
#define VTSS_VMA_TIME_LIMIT (tsc_khz * 30ULL)
#endif

#include "user_vm.h"
#include "utils.h"

#include <linux/slab.h>
#include <linux/vmstat.h>
#include <linux/highmem.h>      /* for kmap()/kunmap() */
#include <linux/pagemap.h>      /* for page_cache_release() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#endif
#include <asm/fixmap.h>         /* VSYSCALL_START */
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#ifdef VTSS_AUTOCONF_NMI_UACCESS
#include <asm/tlbflush.h>
#endif

/*
Virtual memory map with 4 level page tables:

0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
hole caused by [48:63] sign extension
ffff800000000000 - ffff80ffffffffff (=40 bits) guard hole
ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
... unused hole ...
ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
ffffffffa0000000 - fffffffffff00000 (=1536 MB) module mapping space

The direct mapping covers all memory in the system up to the highest
memory address (this means in some cases it can also include PCI memory
holes).

vmalloc space is lazily synchronized into the different PML4 pages of
the processes using the page fault handler, with init_level4_pgt as
reference.

Current X86-64 implementations only support 40 bits of address space,
but we support up to 46 bits. This expands into MBZ space in the page tables.

-Andi Kleen, Jul 2004
*/

#ifdef VTSS_USER_VM_PAGE_PIN
static int vtss_user_vm_page_unpin(struct user_vm_accessor* acc)
{
    if (acc->m_maddr != NULL)
#ifdef VTSS_AUTOCONF_KMAP_ATOMIC_ONE_ARG
        kunmap_atomic(acc->m_maddr);
#else
        kunmap_atomic(acc->m_maddr, in_nmi() ? KM_NMI : KM_IRQ0);
#endif
    acc->m_maddr = NULL;
    if (acc->m_page != NULL)
        put_page(acc->m_page);
    acc->m_page = NULL;
    acc->m_page_id = (unsigned long)-1;
    return 0;
}

#define VTSS_PAGE_ID(addr) (((addr) & PAGE_MASK) >> PAGE_SHIFT)

static int vtss_user_vm_page_pin(struct user_vm_accessor* acc, unsigned long addr)
{
    int rc;

    rc = __get_user_pages_fast(addr, 1, 0, &acc->m_page);
    if (rc != 1) {
        acc->m_page  = NULL;
        acc->m_maddr = NULL;
        acc->m_page_id = (unsigned long)-1;
        return 1;
    }
#ifdef VTSS_AUTOCONF_KMAP_ATOMIC_ONE_ARG
    acc->m_maddr = kmap_atomic(acc->m_page);
#else
    acc->m_maddr = kmap_atomic(acc->m_page, in_nmi() ? KM_NMI : KM_IRQ0);
#endif
    rc = (acc->m_maddr == NULL);
    acc->m_page_id = rc ? (unsigned long)-1 : VTSS_PAGE_ID(addr);
    return rc;
}
#endif

#ifdef VTSS_VMA_SEARCH_BOOST
extern atomic_t vtss_mmap_reg_callcnt;
static void vtss_vma_cache_init(struct user_vm_accessor* acc)
{
    struct vm_area_struct* vma;
    int callcnt = atomic_read(&vtss_mmap_reg_callcnt);
    int is_vdso_found = 0;

    if (!acc) return;
    if (acc->mmap_reg_callcnt >= callcnt) return;
    acc->mmap_reg_callcnt = callcnt;

    acc->mmap_vdso_start = 0;
    acc->mmap_vdso_end = 0;
    acc->mmap_mms_start = 0;
    acc->mmap_mms_end = 0;
    acc->mmap_stack_start = 0;
    acc->mmap_stack_end = 0;

    if (unlikely(!acc->m_mm)) {
         return;
    }

    for (vma = acc->m_mm->mmap; vma != NULL; vma = vma->vm_next) {
            if (vma->vm_mm && vma->vm_start == (long)vma->vm_mm->context.vdso) {
                is_vdso_found = 1;
                acc->mmap_vdso_start = vma->vm_start;
                acc->mmap_vdso_end = vma->vm_end;
            } else if (vma->vm_flags & VM_EXEC) {
                    if (vma->vm_start <= acc->m_mm->start_stack && acc->m_mm->start_stack < vma->vm_end) {
                        acc->mmap_stack_start = vma->vm_start;
                        acc->mmap_stack_end = vma->vm_end;
                    } else if (vma->vm_start !=acc->m_mm->start_code) {
                        if (acc->mmap_mms_start > vma->vm_start || acc->mmap_mms_start == 0)
                            acc->mmap_mms_start = vma->vm_start;
                        if (acc->mmap_mms_end < vma->vm_end)
                            acc->mmap_mms_end = vma->vm_end;
                    }
            }
    }
    if (!is_vdso_found && acc->m_mm->context.vdso) {
        acc->mmap_vdso_start = (unsigned long)acc->m_mm->context.vdso;
        acc->mmap_vdso_end = (unsigned long)acc->m_mm->context.vdso + PAGE_SIZE;
    }
}
#endif

int vtss_user_vm_unlock(struct user_vm_accessor* acc)
{
#ifdef VTSS_USER_VM_PAGE_PIN
    vtss_user_vm_page_unpin(acc);
#endif
    acc->m_mm = NULL;
#ifdef VTSS_VMA_TIME_LIMIT
    acc->m_time = 0;
#endif
    return 0;
}

int vtss_user_vm_trylock(struct user_vm_accessor* acc, struct task_struct* task)
{
    acc->m_mm   = NULL;

    if (task == NULL || task->mm == NULL)
        return 1;

    acc->m_mm = task->mm;
#ifdef VTSS_VMA_TIME_LIMIT
    acc->m_time = get_cycles();
#endif
#ifdef VTSS_VMA_SEARCH_BOOST
    vtss_vma_cache_init(acc);
#endif
    return 0;
}

size_t vtss_user_vm_read(struct user_vm_accessor* acc, void* from, void* to, size_t size)
{
    size_t cpsize, bytes = 0;
    unsigned long offset, addr = (unsigned long)from;
    mm_segment_t old_fs = get_fs();
    long rc;

    set_fs(KERNEL_DS);
    pagefault_disable();

    VTSS_PROFILE_BEGIN(vma);
    do {
#ifdef VTSS_VMA_TIME_LIMIT
        cycles_t access_time = get_cycles();
#endif
        offset = addr & (PAGE_SIZE - 1);
        cpsize = min((size_t)(PAGE_SIZE - offset), size - bytes);
        TRACE("addr=0x%p(0x%lx) size=%zu (page=0x%lx, offset=0x%lx)",
                from, addr, cpsize, page_id, offset);
#ifdef VTSS_VMA_TIME_LIMIT
        if ((access_time - acc->m_time) > acc->m_limit) {
            break; /* Time is over */
        }
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
        if (!access_ok(VERIFY_READ, addr, cpsize))
#else
        if (!access_ok(addr, cpsize))
#endif
            break; /* Don't have a read access */

#ifdef VTSS_USE_NMI
#ifdef VTSS_AUTOCONF_NMI_UACCESS
        if (!nmi_uaccess_okay())
            break; /* unable to access user memory from NMI context */
#endif
#endif

#ifdef VTSS_USER_VM_PAGE_PIN
        if (VTSS_PAGE_ID(addr) != acc->m_page_id) {
            int rc;
            VTSS_PROFILE_BEGIN(pgp);
            vtss_user_vm_page_unpin(acc);
            rc = vtss_user_vm_page_pin(acc, addr);
            VTSS_PROFILE_END(pgp);
            if (rc) {
                TRACE("failed to lock page: addr=%p", addr);
                vtss_user_vm_page_unpin(acc);
                break;
            }
        }
        VTSS_PROFILE(cpy, rc = __copy_from_user_inatomic(to, acc->m_maddr + offset, cpsize));
#else
        VTSS_PROFILE(cpy, rc = __copy_from_user_inatomic(to, (void*)addr, cpsize));
#endif
        if (rc) break;

        bytes += cpsize;
        to    += cpsize;
        addr  += cpsize;
    } while (bytes < size);
    VTSS_PROFILE_END(vma);

    pagefault_enable();
    set_fs(old_fs);

    return bytes;
}

#ifdef VTSS_VMA_SEARCH_BOOST
int vtss_user_vm_validate(struct user_vm_accessor* acc, unsigned long ip)
{
#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    if ((ip >= VSYSCALL_START) && (ip < VSYSCALL_END))
#else
    if ((ip & PAGE_MASK) == VSYSCALL_ADDR)
#endif
        return 1; /* [vsyscall] */
    else
#endif

    if (ip < VTSS_KSTART) {
        struct vm_area_struct* vma = NULL;

        if (!acc || !acc->m_mm) return 0;

        if (!((acc->m_mm->start_code <= ip  && ip < acc->m_mm->end_code) ||
            (acc->mmap_vdso_start <= ip && ip < acc->mmap_vdso_end) ||
            (acc->mmap_stack_start <= ip && ip < acc->mmap_stack_end)  ||
            (acc->mmap_mms_start <= ip && ip < acc->mmap_mms_end) ||
            (acc->m_mm->start_brk <= ip && ip < acc->m_mm->brk) /* for java it can be code */)) {
            return 0;
        }

        vma = find_vma(acc->m_mm, ip);
        if (vma == NULL) {
            return 0;
        }
        if (!((vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_MAYEXEC))) {
            return 0;
        }
        if ((ip >= vma->vm_start) && (ip < vma->vm_end)) {
            return 1;
        }
        return 0;
    } else
        return (ip < PAGE_OFFSET) ? 1 : 0; /* in kernel? */
}
#else
int vtss_user_vm_validate(struct user_vm_accessor* acc, unsigned long ip)
{
#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    if ((ip >= VSYSCALL_START) && (ip < VSYSCALL_END))
#else
    if ((ip & PAGE_MASK) == VSYSCALL_ADDR)
#endif
        return 1; /* [vsyscall] */
    else
#endif
    if (ip < VTSS_KSTART) {
        struct vm_area_struct* vma = acc->m_mm ? find_vma(acc->m_mm, ip) : NULL;
        return ((vma != NULL) && ((vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_MAYEXEC)) && (ip >= vma->vm_start) && (ip < vma->vm_end)) ? 1 : 0;
    } else
        return (ip < PAGE_OFFSET) ? 1 : 0; /* in kernel? */
}
#endif

user_vm_accessor_t* vtss_user_vm_accessor_init(cycles_t limit)
{
    user_vm_accessor_t* acc;

    acc = (user_vm_accessor_t*)vtss_kmalloc(sizeof(user_vm_accessor_t), GFP_ATOMIC);
    if (acc != NULL) {
        memset(acc, 0, sizeof(user_vm_accessor_t));
        acc->m_page_id = (unsigned long)-1;
#ifdef VTSS_VMA_TIME_LIMIT
        acc->m_limit   = limit ? limit : VTSS_VMA_TIME_LIMIT;
#else
        acc->m_limit   = limit;
#endif
        acc->mmap_reg_callcnt = 0;

        acc->mmap_vdso_start = 0;
        acc->mmap_vdso_end = 0;
        acc->mmap_mms_start = 0;
        acc->mmap_mms_end = 0;
        acc->mmap_stack_start = 0;
        acc->mmap_stack_end = 0;
    } else {
        ERROR("No memory for accessor");
    }
    return acc;
}

void vtss_user_vm_accessor_fini(user_vm_accessor_t* acc)
{
    if (acc != NULL) {
        vtss_kfree(acc);
    }
}

int vtss_user_vm_init(void)
{
    return 0;
}

void vtss_user_vm_fini(void)
{
}

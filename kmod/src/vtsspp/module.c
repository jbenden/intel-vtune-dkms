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
#include "module.h"
#include "collector.h"
#include "globals.h"
#include "utils.h"

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
#include <linux/uaccess.h>
#endif
#include <asm/uaccess.h>

#define VTSS_MODULE_AUTHOR "Copyright (C) 2010-2019 Intel Corporation"
#define VTSS_MODULE_NAME   "vtss++ kernel module (" VTSS_TO_STR(VTSS_VERSION_STRING) ")"

int uid = 0;
module_param(uid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(uid, "An user id for profiling");

int gid = 0;
module_param(gid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(gid, "A group id for profiling");

int mode = 0;
module_param(mode, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(mode, "A mode for files in procfs");

#ifdef VTSS_DEBUG_TRACE
static char debug_trace_name[64] = "";
static int  debug_trace_size     = 0;
module_param_string(trace, debug_trace_name, sizeof(debug_trace_name), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(trace, "Turn on trace output from functions starting with this name");

int vtss_check_trace(const char* func_name, int* flag)
{
    return (debug_trace_size && !strncmp(func_name, debug_trace_name, debug_trace_size)) ? 1 : -1;
}
#endif

#ifdef VTSS_USE_TRACEPOINTS
#include <trace/events/sched.h>
#ifdef DECLARE_TRACE_NOARGS
#define VTSS_TP_DATA   , NULL
#define VTSS_TP_PROTO  void *cb_data __attribute__ ((unused)),
#else  /* DECLARE_TRACE_NOARGS */
#define VTSS_TP_DATA
#define VTSS_TP_PROTO
#endif /* DECLARE_TRACE_NOARGS */
#endif /* VTSS_USE_TRACEPOINTS */
#ifdef VTSS_AUTOCONF_TRACE_SCHED_RQ
#define VTSS_TP_RQ struct rq* rq,
#else  /* VTSS_AUTOCONF_TRACE_SCHED_RQ */
#define VTSS_TP_RQ
#endif /* VTSS_AUTOCONF_TRACE_SCHED_RQ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define PREEMPT bool preempt,
#else
#define PREEMPT
#endif

#ifdef VTSS_USE_TRACEPOINTS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
#define VTSS_REGISTER_TRACEPOINT(name)\
{\
    int rc;\
    struct tracepoint *vtss_tracepoint_##name_ptr = (struct tracepoint*)vtss_kallsyms_lookup_name("__tracepoint_"#name);\
    rc = (vtss_tracepoint_##name_ptr) ? tracepoint_probe_register(vtss_tracepoint_##name_ptr, tp_##name VTSS_TP_DATA) : -1;\
    if (rc) {\
        WARNING("Unable to register '"#name"' tracepoint");\
    }\
    else {\
        DEBUG_TP("registered '"#name"' tracepoint");\
        return 0;\
    }\
}
#define VTSS_UNREGISTER_TRACEPOINT(name)\
{\
    int rc;\
    struct tracepoint *vtss_tracepoint_##name_ptr = (struct tracepoint*)vtss_kallsyms_lookup_name("__tracepoint_"#name);\
    rc = (vtss_tracepoint_##name_ptr) ? tracepoint_probe_unregister(vtss_tracepoint_##name_ptr, tp_##name VTSS_TP_DATA) : -1;\
    DEBUG_TP("unregistered '"#name"' tracepoint");\
}
#else
#define VTSS_REGISTER_TRACEPOINT(name)\
{\
    int rc = register_trace_##name(tp_##name VTSS_TP_DATA);\
    if (rc) {\
        WARNING("Unable to register '"#name"' tracepoint");\
    }\
    else {\
        DEBUG_TP("registered '"#name"' tracepoint");\
        return 0;\
    }\
}
#define VTSS_UNREGISTER_TRACEPOINT(name)\
{\
    unregister_trace_##name(tp_##name VTSS_TP_DATA);\
    DEBUG_TP("unregistered '"#name"' tracepoint");\
}
#endif
#else
#define VTSS_REGISTER_TRACEPOINT(name)
#define VTSS_UNREGISTER_TRACEPOINT(name)
#endif

#ifndef VTSS_USE_PREEMPT_NOTIFIERS
#ifdef VTSS_USE_TRACEPOINTS
static void tp_sched_switch(VTSS_TP_PROTO PREEMPT VTSS_TP_RQ struct task_struct *prev, struct task_struct *next)
{
    unsigned long prev_bp = 0;
    unsigned long prev_ip = 0;

    if (prev == current && current != 0)
    {
        VTSS_GET_CURRENT_BP(prev_bp);
        prev_ip = _THIS_IP_;
    }
    vtss_sched_switch(prev, next, prev_bp, prev_ip);
}
#endif

#ifdef VTSS_AUTOCONF_JPROBE
static void jp_sched_switch(VTSS_TP_RQ struct task_struct *prev, struct task_struct *next)
{
    unsigned long prev_bp = 0;
    unsigned long prev_ip = 0;

    if (prev == current && current != 0)
    {
        VTSS_GET_CURRENT_BP(prev_bp);
        prev_ip = _THIS_IP_;
    }
    vtss_sched_switch(prev, next, prev_bp, prev_ip);
    jprobe_return();
}
#endif

#ifdef VTSS_AUTOCONF_JPROBE
static struct jprobe jprobe_sched_switch = {
    .entry = jp_sched_switch
};
#endif

static int probe_sched_switch(void)
{
    VTSS_REGISTER_TRACEPOINT(sched_switch);
#ifdef VTSS_AUTOCONF_JPROBE
    if (vtss_register_jprobe(&jprobe_sched_switch, "context_switch")) {
        if (vtss_register_jprobe(&jprobe_sched_switch, "__switch_to")) {
            ERROR("Unable to register 'context_switch' probe");
            return -1;
        }
    }
#endif
    return 0;
}

static int unprobe_sched_switch(void)
{
    VTSS_UNREGISTER_TRACEPOINT(sched_switch);
#ifdef VTSS_AUTOCONF_JPROBE
    vtss_unregister_jprobe(&jprobe_sched_switch);
#endif
    return 0;
}
#endif

#ifdef VTSS_USE_TRACEPOINTS
static void tp_sched_process_fork(VTSS_TP_PROTO struct task_struct *task, struct task_struct *child)
{
    vtss_target_fork(task, child);
}
#endif

static int rp_sched_process_fork_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    /* Skip kernel threads or if no memory */
    return (current->mm == NULL) ? 1 : 0;
}

static int rp_sched_process_fork_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs_return_value(regs);

    if (pid) {
        struct task_struct *task = vtss_find_task_by_tid(pid);
        if (task) vtss_target_fork(current, task);
        else WARNING("Unable to find pid: %d", pid);
    }
    return 0;
}

static struct kretprobe kretprobe_fork = {
    .entry_handler = rp_sched_process_fork_enter,
    .handler       = rp_sched_process_fork_leave,
    .data_size     = 0
};

static int probe_sched_process_fork(void)
{
    VTSS_REGISTER_TRACEPOINT(sched_process_fork);
    if (vtss_register_kretprobe(&kretprobe_fork, "do_fork")) {
        if (vtss_register_kretprobe(&kretprobe_fork, "_do_fork")) {
            ERROR("Unable to register 'fork' probe");
            return -1;
        }
    }
    return 0;
}

static int unprobe_sched_process_fork(void)
{
    VTSS_UNREGISTER_TRACEPOINT(sched_process_fork);
    vtss_unregister_kretprobe(&kretprobe_fork);
    return 0;
}

/* per-instance private data */
struct rp_sched_process_exec_data
{
    char filename[VTSS_FILENAME_SIZE];
    char config[VTSS_FILENAME_SIZE];
    int ppid;
};

static int compat_exec_probe_user = 0;

// The reason of creating the function below and copping all context from envp rp_sched_process_exec_enter
// is the crash during attempt to get environment in the case when compat_do_execve called.
// TODO: solve the problem and remove this workaround.
static int rp_sched_process_exec_compat_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int i;
    size_t size = 0;
    char *filename = NULL;
    struct rp_sched_process_exec_data *data = (struct rp_sched_process_exec_data*)ri->data;
    if (current == NULL) {
        ERROR("current = NULL");
        return 1; /* Skip kernel threads or if no memory */
    }
    if (current->mm == NULL) {
        ERROR("current->mm = NULL");
        return 1; /* Skip kernel threads or if no memory */
    }
    if (regs == NULL) {
        ERROR("regs==NULL");
        return 1;
    }
#if defined(CONFIG_X86_32)
    filename =  (char*)REG(ax, regs);
#elif defined(CONFIG_X86_64)
    filename =  (char*)REG(di, regs);
#endif
    if (filename != NULL) {
        char* p = filename;
        if (compat_exec_probe_user) {
            i = 0;
            while ((i < VTSS_FILENAME_SIZE - 1) && (vtss_copy_from_user(&data->filename[i], p, 1)==0)) {
                if (data->filename[i] == '/' ) i = 0;
                else if (data->filename[i] == '\0' ) break;
                else i++;
                p++;
            }
            size = i;
        } else {
            p = strrchr(filename, '/');
            p = p ? p+1 : filename;
            TRACE("filename: '%s' => '%s'", filename, p);
            size = min((size_t)VTSS_FILENAME_SIZE-1, (size_t)strlen(p));
            memcpy(data->filename, p, size);
        }
    }
    data->filename[size] = '\0';
    size = 0;
    data->config[size] = '\0';
    data->ppid = TASK_TID(ri->task);
    TRACE("ri=0x%p, data=0x%p, filename='%s', config='%s'", ri, data, data->filename, data->config);
    vtss_target_exec_enter(ri->task, data->filename, data->config);
    return 0;
}

// From the 3.9 do_execve is inlined into sys_execve and probe is broken because of this
// but sys_execve could crash 32bit systems, so we are using do_execve for 32bit
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)) || (defined(CONFIG_X86_32) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)))
#define VTSS_EXEC_PROBE_USER 1
#endif

static int rp_sched_process_exec_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int i;
    size_t size = 0;
    char *filename, **envp;
    struct rp_sched_process_exec_data *data = (struct rp_sched_process_exec_data*)ri->data;

    if (current->mm == NULL)
        return 1; /* Skip kernel threads or if no memory */
#if defined(CONFIG_X86_32)
    filename =  (char*)REG(ax, regs);
    envp     = (char**)REG(cx, regs);
#elif defined(CONFIG_X86_64)
    filename =  (char*)REG(di, regs);
    envp     = (char**)REG(dx, regs);
#endif
    if (filename != NULL) {
        char* p = filename;
#ifdef VTSS_EXEC_PROBE_USER
        i = 0;
        while ((i < VTSS_FILENAME_SIZE - 1) && (vtss_copy_from_user(&data->filename[i], p, 1)==0)) {
            if (data->filename[i] == '/' ) i = 0;
            else if (data->filename[i] == '\0' ) break;
            else i++;
            p++;
        }
        size = i;
#else
        p = strrchr(filename, '/');
        p = p ? p+1 : filename;
        TRACE("filename: '%s' => '%s'", filename, p);
        size = min((size_t)VTSS_FILENAME_SIZE-1, (size_t)strlen(p));
        memcpy(data->filename, p, size);
#endif
    }
    data->filename[size] = '\0';
    size = 0;
#ifdef VTSS_EXEC_PROBE_USER
    if (envp) {
        char *envp_k;
        const char* intel_profile_me = "INTEL_VTSS_PROFILE_ME=";
        while ((vtss_copy_from_user(&envp_k, envp, (sizeof(char*)))==0) && envp_k != NULL) {
            i = 0;
            while ((i < 22 ) && (vtss_copy_from_user(&data->config[i], envp_k, 1)==0)) {
                if (data->config[i] != intel_profile_me[i] ) break;
                else i++;
                envp_k++;
            }
            if (i != 22) break;
            i = 0;
            while ((i < VTSS_FILENAME_SIZE - 1) && (vtss_copy_from_user(&data->config[i], envp_k, 1)==0)) {
                if (data->config[i] == '\0' ) break;
                else i++;
                envp_k++;
            }
            envp++;
        }
    }
#else
    if (envp) for (i = 0; envp[i] != NULL; i++) {
        TRACE("env[%d]: '%s'\n", i, envp[i]);
        if (!strncmp(envp[i], "INTEL_VTSS_PROFILE_ME=", 22 /*==strlen("INTEL_VTSS_PROFILE_ME=")*/)) {
            char *config = envp[i]+22; /*==strlen("INTEL_VTSS_PROFILE_ME=")*/
            size = min((size_t)VTSS_FILENAME_SIZE-1, (size_t)strlen(config));
            memcpy(data->config, config, size);
            break;
        }
    }
#endif
    data->config[size] = '\0';
    data->ppid = TASK_TID(ri->task);
    TRACE("ri=0x%p, data=0x%p, filename='%s', config='%s'", ri, data, data->filename, data->config);
    vtss_target_exec_enter(ri->task, data->filename, data->config);
    return 0;
}

static int rp_sched_process_exec_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct rp_sched_process_exec_data *data = (struct rp_sched_process_exec_data*)ri->data;
    int rc = regs_return_value(regs);
    if (!data) {
        ERROR("data is null");
        return 0;
    }
    if (data->filename)TRACE("ri=0x%p, data=0x%p, filename='%s', config='%s', rc=%d", ri, data, data->filename, data->config, rc);
    vtss_target_exec_leave(ri->task, data->filename, data->config, rc, data->ppid);
    return 0;
}

static struct kretprobe kretprobe_exec = {
    .entry_handler = rp_sched_process_exec_enter,
    .handler       = rp_sched_process_exec_leave,
    .data_size     = sizeof(struct rp_sched_process_exec_data)
};

static int probe_sched_process_exec(void)
{
    int rc = 0;
#ifdef VTSS_EXEC_PROBE_USER
    rc = vtss_register_kretprobe(&kretprobe_exec, "sys_execve");
    if (rc) rc = vtss_register_kretprobe(&kretprobe_exec, "__x64_sys_execve");
#else
    rc = vtss_register_kretprobe(&kretprobe_exec, "do_execve");
#endif
    if (rc) ERROR("Unable to register 'execve' probe");
    return rc;
}

static int unprobe_sched_process_exec(void)
{
    vtss_unregister_kretprobe(&kretprobe_exec);
    return 0;
}

#ifdef CONFIG_COMPAT
static struct kretprobe kretprobe_exec_compat = {
    .entry_handler = rp_sched_process_exec_compat_enter,
    .handler       = rp_sched_process_exec_leave,
    .data_size     = sizeof(struct rp_sched_process_exec_data)
};

static int probe_sched_process_exec_compat(void)
{
    compat_exec_probe_user = 0;
    if (vtss_register_kretprobe(&kretprobe_exec_compat, "compat_do_execve")) {
        if (vtss_register_kretprobe(&kretprobe_exec_compat, "compat_sys_execve")) {
            if (vtss_register_kretprobe(&kretprobe_exec_compat, "__x32_compat_sys_execve")) {
                WARNING("Profiling of 32bit applications is disabled");
            }
        }
        compat_exec_probe_user = 1;
    }
    return 0;
}

static int unprobe_sched_process_exec_compat(void)
{
    return vtss_unregister_kretprobe(&kretprobe_exec_compat);
}
#endif

#ifdef VTSS_USE_TRACEPOINTS
static void tp_sched_process_exit(VTSS_TP_PROTO struct task_struct *task)
{
    vtss_target_exit(task);
}
#endif

static int kp_sched_process_exit(struct kprobe *p, struct pt_regs *regs)
{
    vtss_target_exit(current);
    return 0;
}

static struct kprobe kprobe_exit = {
    .pre_handler = kp_sched_process_exit,
    .post_handler = NULL
};

static int probe_sched_process_exit(void)
{
    VTSS_REGISTER_TRACEPOINT(sched_process_exit);
    if (vtss_register_kprobe(&kprobe_exit, "do_exit")) {
        ERROR("Unable to register 'exit' probe");
        return -1;
    }
    return 0;
}

static int unprobe_sched_process_exit(void)
{
    VTSS_UNREGISTER_TRACEPOINT(sched_process_exit);
    vtss_unregister_kprobe(&kprobe_exit);
    return 0;
}

/* per-instance private data */
struct rp_mmap_region_data
{
    struct file*  file;
    unsigned long addr;
    unsigned long size;
    unsigned long pgoff;
    unsigned int  flags;
};

static int rp_mmap_region_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct rp_mmap_region_data *data = (struct rp_mmap_region_data*)ri->data;

    if (current->mm == NULL)
        return 1; /* Skip kernel threads or if no memory */
#if defined(CONFIG_X86_32)
    data->file  = (struct file*)REG(ax, regs);
    data->addr  = REG(dx, regs);
    data->size  = REG(cx, regs);
    /* get the rest from stack */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    data->flags = ((int32_t*)&REG(sp, regs))[2]; /* vm_flags */
    data->pgoff = data->file ? ((int32_t*)&REG(sp, regs))[3] : 0;
#else
    data->flags = ((int32_t*)&REG(sp, regs))[1]; /* vm_flags */
    data->pgoff = data->file ? ((int32_t*)&REG(sp, regs))[2] : 0;
#endif
#elif defined(CONFIG_X86_64)
    data->file  = (struct file*)REG(di, regs);
    data->addr  = REG(si, regs);
    data->size  = REG(dx, regs);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    data->flags = REG(r8, regs); /* vm_flags */
    data->pgoff = data->file ? REG(r9, regs) : 0;
#else
    data->flags = REG(cx, regs); /* vm_flags */
    data->pgoff = data->file ? REG(r8, regs) : 0;
#endif
#endif
    return 0;
}

static int rp_mmap_region_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct rp_mmap_region_data *data = (struct rp_mmap_region_data*)ri->data;
    unsigned long rc = regs_return_value(regs);

    if ((rc == data->addr) &&
        (data->flags & VM_EXEC) && !(data->flags & VM_WRITE) &&
        data->file && data->file->f_path.dentry)
    {
        TRACE("file=0x%p, addr=0x%lx, pgoff=%lu, size=%lu, flags=0x%x", data->file, data->addr, data->pgoff, data->size, data->flags);
        vtss_mmap(data->file, data->addr, data->pgoff, data->size);
    }
    return 0;
}

static struct kretprobe kretprobe_mmap_region = {
    .entry_handler = rp_mmap_region_enter,
    .handler       = rp_mmap_region_leave,
    .data_size     = sizeof(struct rp_mmap_region_data)
};

static int probe_mmap_region(void)
{
    if (vtss_register_kretprobe(&kretprobe_mmap_region, "mmap_region")) {
        ERROR("Unable to register 'mmap' probe");
        return -1;
    }
    return 0;
}

static int unprobe_mmap_region(void)
{
    vtss_unregister_kretprobe(&kretprobe_mmap_region);
    return 0;
}

#ifdef VTSS_SYSCALL_TRACE
static int kp_syscall_enter(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs* sregs;

    if (current->mm == NULL)
        return 1; /* Skip kernel threads or if no memory */
#if defined(CONFIG_X86_32)
    sregs = (struct pt_regs*)REG(ax, regs);
#elif defined(CONFIG_X86_64)
    sregs = (struct pt_regs*)REG(di, regs);
#endif
    vtss_syscall_enter(sregs);
    return 0;
}

static int kp_syscall_leave(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs* sregs;

    if (current->mm == NULL)
        return 1; /* Skip kernel threads or if no memory */
#if defined(CONFIG_X86_32)
    sregs = (struct pt_regs*)REG(ax, regs);
#elif defined(CONFIG_X86_64)
    sregs = (struct pt_regs*)REG(di, regs);
#endif
    vtss_syscall_leave(sregs);
    return 0;
}

static struct kprobe kprobe_syscall_enter = {
    .pre_handler = kp_syscall_enter,
    .post_handler = NULL
};

static struct kprobe kprobe_syscall_leave = {
    .pre_handler = kp_syscall_leave,
    .post_handler = NULL
};

static int probe_syscall_trace(void)
{
    if (vtss_register_kprobe(&kprobe_syscall_leave, "syscall_trace_leave") == 0) {
        if (vtss_register_kprobe(&kprobe_syscall_enter, "syscall_trace_enter")) {
            WARNING("System calls tracing is disabled");
        }
    }
    return 0;
}

static int unprobe_syscall_trace(void)
{
    vtss_unregister_kprobe(&kprobe_syscall_leave);
    vtss_unregister_kprobe(&kprobe_syscall_enter);
}
#endif /* VTSS_SYSCALL_TRACE */

/* kernel module notifier */
static int vtss_kmodule_notifier(struct notifier_block *block, unsigned long val, void *data)
{
    struct module *mod = (struct module*)data;
    const char *name = mod->name;
#ifdef VTSS_AUTOCONF_MODULE_CORE_LAYOUT
    unsigned long module_core = (unsigned long)mod->core_layout.base;
    unsigned long core_size = mod->core_layout.size;
#else
    unsigned long module_core = (unsigned long)mod->module_core;
    unsigned long core_size = mod->core_size;
#endif
    if (val == MODULE_STATE_COMING) {
        TRACE("MODULE_STATE_COMING: name='%s', module_core=0x%lx, core_size=%lu", name, module_core, core_size);
        vtss_kmap(current, name, module_core, 0, core_size);
    } else if (val == MODULE_STATE_GOING) {
        TRACE("MODULE_STATE_GOING:  name='%s'", name);
    }
    return NOTIFY_DONE;
}

static struct notifier_block vtss_kmodules_nb = {
    .notifier_call = &vtss_kmodule_notifier
};

static int probe_kmodules(void)
{
    return register_module_notifier(&vtss_kmodules_nb);
}

static int unprobe_kmodules(void)
{
    return unregister_module_notifier(&vtss_kmodules_nb);
}

int vtss_probe_init(void)
{
    int rc = 0;
#ifdef VTSS_SYSCALL_TRACE
    rc |= probe_syscall_trace();
#endif
    rc |= probe_sched_process_exit();
    rc |= probe_sched_process_fork();
#ifdef CONFIG_COMPAT
    rc |= probe_sched_process_exec_compat();
#endif
    rc |= probe_sched_process_exec();
    rc |= probe_mmap_region();
    rc |= probe_kmodules();
#ifndef VTSS_USE_PREEMPT_NOTIFIERS
    rc |= probe_sched_switch();
#endif
    return rc;
}

void vtss_probe_fini(void)
{
#ifndef VTSS_USE_PREEMPT_NOTIFIERS
    unprobe_sched_switch();
#endif
    unprobe_kmodules();
    unprobe_mmap_region();
    unprobe_sched_process_exec();
#ifdef CONFIG_COMPAT
    unprobe_sched_process_exec_compat();
#endif
    unprobe_sched_process_fork();
    unprobe_sched_process_exit();
#ifdef VTSS_SYSCALL_TRACE
    unprobe_syscall_trace();
#endif
#ifdef VTSS_USE_TRACEPOINTS
    tracepoint_synchronize_unregister();
#endif
}

/* ----- module init/fini ----- */

void cleanup_module(void)
{
    vtss_fini();
    REPORT("Driver has been unloaded");
}

int init_module(void)
{
    int rc = 0;

#ifdef VTSS_DEBUG_TRACE
    if (*debug_trace_name != '\0')
        debug_trace_size = strlen(debug_trace_name);
#endif

    REPORT("Driver version %s", VTSS_VERSION_STRING);

    rc = vtss_init();

    if (!rc) {
        REPORT("Driver has been loaded");
    } else {
        REPORT("Initialization failed");
        vtss_fini();
    }
    return rc;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR(VTSS_MODULE_AUTHOR);
MODULE_DESCRIPTION(VTSS_MODULE_NAME);

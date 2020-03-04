#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <asm/ptrace.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/uaccess.h>
#include "trace_process.h"
/* per-instance private data */



static int __init hook_syscall_init(void) {
    if(0 != kretprobe_fork_init()){
        printk("Failed to init fork\n");
        return -1;
    }
    
    if(0 != kprobe_execve_init()){
        printk("Failed to init execve\n");
        kretprobe_fork_exit();
        return -1;
    }

    if(0 != kprobe_setns_init()){
        printk("Failed to init setns\n");
        kretprobe_fork_exit();
        kprobe_execve_exit();
        return -1;
    }

    printk("Kprobe and kretprobe successfully!\n");

	return 0;
}

static void __exit hook_syscall_exit(void) {
    kprobe_execve_exit();
    kprobe_setns_exit();
    kretprobe_fork_exit();
}

module_init(hook_syscall_init)
module_exit(hook_syscall_exit)
MODULE_LICENSE("GPL");

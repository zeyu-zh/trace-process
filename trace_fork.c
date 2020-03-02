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

static char *fork_name = "_do_fork";

static int fork_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){ return 0; }

static int fork_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    unsigned long retval = regs_return_value(regs);

    printk("SYS_fork: <%s>(pid=%d ppid=%d tgid=%d) invokes fork() = %d\n",
        current->comm, current->pid, current->parent->pid, current->tgid, retval);
    
    return 0;
}

static struct kretprobe fork_kretprobe = {
    .handler = fork_ret_handler,
    .entry_handler = fork_entry_handler,
    .maxactive = 30,
};

int kretprobe_fork_init(void){
    fork_kretprobe.kp.symbol_name = fork_name;
    int ret = register_kretprobe(&fork_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}

    return 0;
}

int kretprobe_fork_exit(void){
	unregister_kretprobe(&fork_kretprobe);
	pr_info("kretprobe at %p unregistered\n", fork_kretprobe.kp.addr);

    return 0;
}



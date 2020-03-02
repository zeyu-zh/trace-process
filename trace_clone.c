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

static char *clone_name = "sys_clone";

static int clone_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){ return 0; }

static int clone_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    unsigned long retval = regs_return_value(regs);

    printk("SYS_clone: <%s>(%d) invokes clone() = %d\n",
        current->comm, current->pid, retval);
    
    return 0;
}

static struct kretprobe clone_kretprobe = {
    .handler = clone_ret_handler,
    .entry_handler = clone_entry_handler,
    .maxactive = 30,
};

int kretprobe_clone_init(void){
    clone_kretprobe.kp.symbol_name = clone_name;
    int ret = register_kretprobe(&clone_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}

    return 0;
}

int kretprobe_clone_exit(void){
	unregister_kretprobe(&clone_kretprobe);
	pr_info("kretprobe at %p unregistered\n", clone_kretprobe.kp.addr);

    return 0;
}



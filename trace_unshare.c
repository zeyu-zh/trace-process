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
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include "trace_process.h"

static char *unshare_name = "sys_unshare";
extern int parse_flags(uint64_t flags, char* str_buffer, int len);

static int unshare_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    /* only if the it is a valid parameter */
    uint64_t flags = regs->di;
    char str_flags[350];

    parse_flags(flags, str_flags, 350);
    printk("SYS_unshare: <%s>(pid=%d ppid=%d tgid=%d) invokes unshare(%s)\n",
        current->comm, current->pid, current->parent->pid, current->tgid, str_flags);
    return 0;
}


static void unshare_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) { }


static int unshare_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	//pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
    /* no.14 means the page fault exception */
	/* Return 0 because we don't handle the fault. */
	return 0;
}


static struct kprobe unshare_kprobe = {	
    .pre_handler = unshare_handler_pre,
	.post_handler = unshare_handler_post,
	.fault_handler = unshare_handler_fault,
};


int kprobe_unshare_init(void){
    unshare_kprobe.symbol_name = unshare_name;
	int ret = register_kprobe(&unshare_kprobe);
	if (ret < 0) {
		pr_err("register_kprobe(unshare) failed, returned %d\n", ret);
		return ret;
	}

    return 0;
}

int kprobe_unshare_exit(void){
	unregister_kprobe(&unshare_kprobe);
	pr_info("kprobe(unshare) at %p unregistered\n", unshare_kprobe.addr);

    return 0;
}
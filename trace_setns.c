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

static char *setns_name = "sys_setns";


uint64_t nstype_table[] = {CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET};

char* str_nstype_table[] = {"NEWNS", "NEWCGROUP", "NEWUTS", "NEWIPC", "NEWUSER", "NEWPID", "NEWNET"};
extern int parse_flags(uint64_t flags, char* str_buffer, int len);

static int setns_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    /* only if the it is a valid parameter */
    int fd = regs->di, len_str = 0, i;
    char str_flags[350];
    uint64_t nstype = nstype = regs->si;

    parse_flags(nstype, str_flags, 350);
    printk("SYS_setns: <%s>(pid=%d ppid=%d tgid=%d) invokes setns(%d, %s)\n",
        current->comm, current->pid, current->parent->pid, current->tgid, fd, str_flags);
    return 0;
}


static void setns_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) { }


static int setns_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	//pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
    /* no.14 means the page fault exception */
	/* Return 0 because we don't handle the fault. */
	return 0;
}


static struct kprobe setns_kprobe = {	
    .pre_handler = setns_handler_pre,
	.post_handler = setns_handler_post,
	.fault_handler = setns_handler_fault,
};


int kprobe_setns_init(void){
    setns_kprobe.symbol_name = setns_name;
	int ret = register_kprobe(&setns_kprobe);
	if (ret < 0) {
		pr_err("register_kprobe(setns) failed, returned %d\n", ret);
		return ret;
	}

    return 0;
}

int kprobe_setns_exit(void){
	unregister_kprobe(&setns_kprobe);
	pr_info("kprobe(setns) at %p unregistered\n", setns_kprobe.addr);

    return 0;
}
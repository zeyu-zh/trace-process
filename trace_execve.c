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

static char *execve_name = "sys_execve";

static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    /* only if the it is a valid parameter */
    if (regs->di != 0 && regs->si != 0) {
        /* get the file name to be executed */
        char log[512] = {0};
        char* argv = (char*)(regs->si), *str;

        copy_from_user(&str, argv, sizeof(char*));
        int len = 0;

        if(str != NULL)
            len = strnlen_user(str, MAX_ARG_STRLEN);
        else
            return 0;
        if (!len) return 0;

        if(len > 500)
            printk("Error: too long!\n");
        else {
            copy_from_user(log, str, len);
            printk("SYS_execve: <%s>(pid=%d ppid=%d tgid=%d) invokes execve(%s)",
                current->comm, current->pid, current->parent->pid, current->tgid, log);
        }
    }

    return 0;
}


static void execve_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) { }


static int execve_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	//pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
    /* no.14 means the page fault exception */
	/* Return 0 because we don't handle the fault. */
	return 0;
}


static struct kprobe execve_kprobe = {	
    .pre_handler = execve_handler_pre,
	.post_handler = execve_handler_post,
	.fault_handler = execve_handler_fault,
};


int kprobe_execve_init(void){
    execve_kprobe.symbol_name = execve_name;
	int ret = register_kprobe(&execve_kprobe);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

    return 0;
}

int kprobe_execve_exit(void){
	unregister_kprobe(&execve_kprobe);
	pr_info("kprobe at %p unregistered\n", execve_kprobe.addr);

    return 0;
}
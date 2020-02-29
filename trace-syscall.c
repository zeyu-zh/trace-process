/*
 * kretprobe_example.c
 *
 * Here's a sample kernel module showing the use of return probes to
 * report the return value and total time taken for probed function
 * to run.
 *
 * usage: insmod kretprobe_example.ko func=<func_name>
 *
 * If no func_name is specified, do_fork is instrumented
 *
 * For more information on theory of operation of kretprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the console
 * whenever the probed function returns. (Some messages may be suppressed
 * if syslogd is configured to eliminate duplicate messages.)
 */

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
/* per-instance private data */







static char execve_name[64] = "sys_execve";
static char clone_name[64] = "sys_clone";
module_param_string(clone_name, clone_name, NAME_MAX, S_IRUGO);
module_param_string(execve_name, execve_name, NAME_MAX, S_IRUGO);



static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    if(current->comm != NULL && regs->di != 0){
        int len = strnlen_user(regs->di, 100);
        char* name = kmalloc(len > 100 ? len : 100 ,GFP_KERNEL);
        copy_from_user(name, regs->di, len);
        printk("SyS_execve: current task(%d) is %s  execve(%s)\n", 
            current->pid, current->comm, name);
    }

    
    
    return 0;
}

static void execve_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) {
	// pr_info("<%s> post_handler: p->addr = 0x%p, flags = 0x%lx\n",
	// 	p->symbol_name, p->addr, regs->flags);
}

static int execve_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static int clone_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){ return 0; }


static int clone_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    unsigned long retval = regs_return_value(regs);

    printk(KERN_INFO "SYS_CLONE: current task(%d) is %s, the return value is %d\n",
        current->pid, current->comm, retval);
    
    return 0;
}


static struct kretprobe clone_kretprobe = {
    .handler = clone_ret_handler,
    .entry_handler = clone_entry_handler,
    .maxactive = 20,
};

static struct kprobe execve_kprobe = {	
    .pre_handler = execve_handler_pre,
	.post_handler = execve_handler_post,
	.fault_handler = execve_handler_fault,
};




static int __init hook_syscall_init(void) {
	int ret;

    clone_kretprobe.kp.symbol_name = clone_name;
    ret = register_kretprobe(&clone_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}

    execve_kprobe.symbol_name = execve_name;
	ret = register_kprobe(&execve_kprobe);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
    printk("Kprobe and kretprobe successfully!\n");

	return 0;
}

static void __exit hook_syscall_exit(void) {
	unregister_kretprobe(&clone_kretprobe);
	pr_info("kretprobe at %p unregistered\n", clone_kretprobe.kp.addr);

	unregister_kprobe(&execve_kprobe);
	pr_info("kprobe at %p unregistered\n", execve_kprobe.addr);
}

module_init(hook_syscall_init)
module_exit(hook_syscall_exit)
MODULE_LICENSE("GPL");

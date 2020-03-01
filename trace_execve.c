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
#include "trace_process.h"

static char *execve_name = "sys_execve";


/*
 * count() counts the number of strings in array ARGV. linux-4.15.1
 */
static int count(struct user_arg_ptr argv, int max) {
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p) break;
			if (IS_ERR(p)) return -EFAULT;
			if (i >= max) return -E2BIG;

			++i;
			if (fatal_signal_pending(current)) return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    /* only if the it is a valid parameter */
    if (regs->di != 0) {
        /* get the file name to be executed */
        struct filename *filename = getname(regs->di);
        struct user_arg_ptr argv = { .ptr.native = regs->si };
        char log[512] = {0};
        int log_len = 0;

        int argc = count(argv, MAX_ARG_STRINGS);
        if (argc < 0)
            goto out;

        if (current->comm)
            sprintf(log+log_len, "SyS_execve: %s(%d) invokes execve(%s, [",
                current->comm, current->pid, filename->name);
        else
            sprintf(log+log_len, "SyS_execve: UNKNOW_NAME(%d) invokes execve(%s, [",
                current->pid, filename->name);
        log_len = strlen(log);

        while (argc-- > 0) {
            char __user *str = get_user_arg_ptr(argv, argc);
            if (IS_ERR(str)) goto out;

            int len = strnlen_user(str, MAX_ARG_STRLEN);
		    if (!len) goto out;

            copy_from_user(log+log_len, str, len);
            log_len = log_len + len;
            log[log_len] = ',';
            log[log_len+1] = ' ';
            log_len = log_len + 2;
        }

        strcpy(log+log_len-2, "])");
        printk("%s\n", log);

out:
        putname(filename);
    }
    
    return 0;
}


static void execve_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) { }


static int execve_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
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
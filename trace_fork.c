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
#include <linux/sched.h>
#include <linux/signal.h>
#include "trace_process.h"


// /*
//  * cloning flags:
//  */
// #define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
// #define CLONE_VM	0x00000100	/* set if VM shared between processes */
// #define CLONE_FS	0x00000200	/* set if fs info shared between processes */
// #define CLONE_FILES	0x00000400	/* set if open files shared between processes */
// #define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
// #define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
// #define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
// #define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
// #define CLONE_THREAD	0x00010000	/* Same thread group? */
// #define CLONE_NEWNS	0x00020000	/* New mount namespace group */
// #define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
// #define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
// #define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
// #define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
// #define CLONE_DETACHED		0x00400000	/* Unused, ignored */
// #define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
// #define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
// #define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
// #define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
// #define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
// #define CLONE_NEWUSER		0x10000000	/* New user namespace */
// #define CLONE_NEWPID		0x20000000	/* New pid namespace */
// #define CLONE_NEWNET		0x40000000	/* New network namespace */
// #define CLONE_IO		0x80000000	/* Clone io context */

static char *fork_name = "_do_fork";

uint64_t flags_table[] = {CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER, 
                        CLONE_NEWPID,CLONE_NEWNET,    CLONE_VM,     CLONE_FS,     CLONE_FILES,
                        CLONE_SIGHAND, CLONE_PTRACE,  CLONE_VFORK,  CLONE_PARENT, CLONE_THREAD,
                        CLONE_SYSVSEM, CLONE_SETTLS,  CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID,
                        CLONE_DETACHED, CLONE_UNTRACED, CLONE_CHILD_SETTID, CLONE_IO, 17};

char* str_flags_table[] = {"NEWNS", "NEWCGROUP", "NEWUTS", "NEWIPC", "NEWUSER",
                         "NEWPID", "NEWNET",   "VM",     "FS",     "FILES",
                         "SIGHAND", "PTRACE",  "VFORK",  "PARENT", "THREAD",
                         "SYSVSEM", "SETTLS",  "PARENT_SETTID", "CHILD_CLEARTID",
                         "DETACHED", "UNTRACED", "CHILD_SETTID", "IO", "CSIGNAL"};

/* per-instance private data */
struct my_data {
	uint64_t flags;
    int __user *parent_tidptr;
    int __user *child_tidptr;
};

static int fork_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){     
    struct my_data *data;

    /* Skip kernel threads */
	if (!current->mm)
		return 1;	

	data = (struct my_data *)ri->data;
	data->flags = regs->di;
    data->parent_tidptr = regs->r10;
    data->child_tidptr = regs->r8;

    return 0; 

}

static int fork_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    unsigned long retval = regs_return_value(regs);
    struct my_data *data = (struct my_data *)ri->data;
    uint64_t flags = data->flags;
    char str_flags[350];
    int len_str = 0, i, parent_tid, child_tid;
    int __user *parent_tidptr = data->parent_tidptr, *child_tidptr = data->child_tidptr;


    memset(str_flags, 0, 350);
    for (i = 0; i < sizeof(flags_table) / 8; i++) {
        if((flags & flags_table[i]) == (flags_table[i])){
            sprintf(str_flags + len_str, "%s | ", str_flags_table[i]);
            len_str = len_str + strlen(str_flags_table[i]) + 3;
        }
    }


    if(len_str != 0)
        str_flags[len_str-2] = '\0';
    len_str = strlen(str_flags);

    if ((flags & CLONE_PARENT_SETTID) == (CLONE_PARENT_SETTID)) {
        if (parent_tidptr != NULL) {
            copy_from_user(&parent_tid, parent_tidptr, sizeof(int));
            sprintf(str_flags + len_str, "ptid=%d", parent_tid);
            len_str = len_str + strlen(str_flags + len_str);
        } else {
            sprintf(str_flags + len_str, "ptid=0");
            len_str = len_str + 6;
        }
    }

    if((flags & CLONE_CHILD_SETTID) == (CLONE_CHILD_SETTID)){
        if (child_tidptr != NULL) {
            copy_from_user(&child_tid, child_tidptr, sizeof(int));
            sprintf(str_flags + len_str, "ctid=%d ", child_tid);
            len_str = len_str + strlen(str_flags + len_str);
        } else {
            sprintf(str_flags + len_str, "ctid=0");
            len_str = len_str + 6;
        }
    }



    printk("SYS_fork: <%s>(pid=%d ppid=%d tgid=%d) invokes fork(%s) = %d\n",
        current->comm, current->pid, current->parent->pid, current->tgid, str_flags, retval);
    
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



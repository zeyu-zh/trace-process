#ifndef _TRACE_PROCESS_H_
#define _TRACE_PROCESS_H_

int kretprobe_fork_init(void);
int kretprobe_fork_exit(void);
int kprobe_execve_init(void);
int kprobe_execve_exit(void);
int kprobe_setns_init(void);
int kprobe_setns_exit(void);
int kprobe_unshare_init(void);
int kprobe_unshare_exit(void);
#endif
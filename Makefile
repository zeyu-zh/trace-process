# builds the kprobes example kernel modules;
# then to use one (as root):  insmod <module_name.ko>

obj-y += trace_process.o trace_clone.o trace_execve.o
obj-m += trace_syscall.o

KERNEL_VER := $(shell uname -r)
KERNEL_DIR := /lib/modules/$(KERNEL_VER)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

insmod:
	sudo insmod trace_syscall.ko

rmmod:
	sudo rmmod trace_syscall

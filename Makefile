# builds the kprobes example kernel modules;
# then to use one (as root):  insmod <module_name.ko>

obj-m += trace-syscall.o

KERNEL_VER := $(shell uname -r)
KERNEL_DIR := /lib/modules/$(KERNEL_VER)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

insmod:
	sudo insmod kretprobe.ko

rmmod:
	sudo rmmod kretprobe

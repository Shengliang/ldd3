obj-m := vdev_module.o
vdev_module-objs = vdev_blk.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
kmodule:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

load:
	sudo dmesg -c
	sudo insmod vdev_module.ko

rm:
	sudo rmmod vdev_module.ko

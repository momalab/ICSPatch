PWD := $(shell pwd)
obj-m += patcher.o
CROSS = /usr/bin/arm-none-eabi-
KERNEL = ../KERNEL/

all:
	make ARCH=arm CROSS_COMPILE=$(CROSS) -C $(KERNEL) SUBDIRS=$(PWD) CFLAGS_MODULE=-fno-pic modules
clean:
	make -C $(KERNEL) SUBDIRS=$(PWD) clean

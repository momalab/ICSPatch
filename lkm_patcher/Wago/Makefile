PWD := $(shell pwd)
obj-m += wago_patcher.o
CROSS = /usr/bin/arm-none-eabi-
KERNEL = ../linux-5.10.21/

all:
	make ARCH=arm CROSS_COMPILE=$(CROSS) -C $(KERNEL) M=$(PWD) CFLAGS_MODULE=-fno-pic modules
clean:
	make -C $(KERNEL) M=$(PWD) clean

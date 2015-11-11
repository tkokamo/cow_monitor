# Makefile
obj-m += cow_mem.o 
smallmod-objs := interval_tree.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

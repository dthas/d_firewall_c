obj-m := modules.o
modules-objs := mymodule.o

#KDIR := /lib/modules/`uname -r`/build
KDIR := /usr/src/linux-headers-$(shell uname -r)
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:	rclean rclean
	
fclean:
	rm -f *.o *.cmd *.ko *.mod.c

rclean:
	rm -r *.tmp*

#===========================================================================
# Makefile
#
#   Copyright (C) 2016 Free Software Foundation, Inc.
#   Originally by ZhaoFeng Liang <zhf.liang@hotmail.com>
#
#This file is part of DTHAS.
#
#DTHAS is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2 of the License, or 
#(at your option) any later version.
#
#DTHAS is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with DTHAS; If not, see <http://www.gnu.org/licenses/>.  
#===========================================================================

obj-m = dfirewall.o
dfirewall-objs 	= pre_routing.o post_routing.o local_in.o local_out.o forward.o lib.o main.o

KDIR 		:= /usr/src/linux-headers-$(shell uname -r)

all:	realclean mod clean

mod:
	make -C $(KDIR) M=`pwd` modules

realclean:
	rm -rf *.o *.cmd .tmp* *.ko.cmd *.mod.c *.o.cmd .*.mod.o.cmd .*.ko.cmd .*.o.cmd *.ko

clean:
	rm -rf *.o *.cmd .tmp* *.ko.cmd *.mod.c *.o.cmd .*.mod.o.cmd .*.ko.cmd .*.o.cmd

install:
	sudo insmod dfirewall.ko

remove:
	sudo rmmod dfirewall

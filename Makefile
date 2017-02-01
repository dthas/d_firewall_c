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

# Programs, flags, etc.
ASM		= nasm
#DASM		= ndisasm
CC		= gcc
LD		= ld

#obj-m 		:= dfirewall.o
#KDIR 		:= /usr/src/linux-headers-$(shell uname -r)


ASMLIBFLAGS	= -I src/include/ -I src/lib/ -f elf

CFLAGS		= -I src/include/ -c -fno-builtin -w -fno-stack-protector
#CFLAGS		= -I src/include/ -I /usr/src/linux-headers-4.4.0-57/include -I /usr/src/linux-headers-4.4.0-57/arch/x86/include -I /usr/src/linux-headers-4.4.0-57-generic/include -I /usr/src/linux-headers-4.4.0-57-generic/arch/x86/include/generated -c -fno-builtin -w -fno-stack-protector
LDFLAGS		= -Map proc.map $(LOBJS_UBUNTU)
ARFLAGS		= rcs

# This Program
PROC		= dst/dfc
LIB		= dst/dfc.a

OBJS		= $(OBJS_MAIN) $(OBJS_TEST)\
			$(OBJS_PROTO)
			
OBJS_MAIN	= src/main/main.o

OBJS_PROTO	= src/proto/f_http_dns.o\
			src/proto/f_http_port.o\
			src/proto/f_http_ip.o
			

LOBJS		=  src/lib/strings.o\
			src/lib/lib.o
						

LOBJS_UBUNTU	= /usr/lib/x86_64-linux-gnu/crt1.o\
			/usr/lib/x86_64-linux-gnu/crti.o\
			/usr/lib/gcc/x86_64-linux-gnu/5.4.0/crtbegin.o\
			-lc /usr/lib/gcc/x86_64-linux-gnu/5.4.0/crtend.o\
			/usr/lib/x86_64-linux-gnu/crtn.o\
			-dynamic-linker /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

#OBJS_TEST	=  src/main/test.o


#mod:
#	make -C $(KDIR) M=`pwd` modules
#
#install:
# 	/sbin/insmod dfirewall.ko
#
#remove:
# 	/sbin/rmmod dfirewall
						

all : realclean everything clean

realclean :
	rm -f  $(OBJS) $(LOBJS) $(LIB)

clean :
	rm -f $(OBJS) $(LOBJS) 

everything : $(PROC) $(OBJS) $(LOBJS)

$(PROC) : $(OBJS) $(LIB) 
	$(LD) $(LDFLAGS) -o $(PROC) $^

$(LIB) : $(LOBJS)
	$(AR) $(ARFLAGS) $@ $^

src/lib/strings.o: src/lib/strings.c
	$(CC) $(CFLAGS) -o $@ $<

src/lib/lib.o: src/lib/lib.c
	$(CC) $(CFLAGS) -o $@ $<

src/main/main.o: src/main/main.c
	$(CC) $(CFLAGS) -o $@ $<

#src/main/test.o: src/main/test.cpp
#	$(CC) $(CFLAGS) -o $@ $<

src/proto/f_http_dns.o: src/proto/f_http_dns.c
	$(CC) $(CFLAGS) -o $@ $<

src/proto/f_http_ip.o: src/proto/f_http_ip.c
	$(CC) $(CFLAGS) -o $@ $<

src/proto/f_http_port.o: src/proto/f_http_port.c
	$(CC) $(CFLAGS) -o $@ $<

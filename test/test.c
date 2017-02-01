//===========================================================================
// test.c
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Originally by ZhaoFeng Liang <zhf.liang@hotmail.com>
//
//This file is part of DTHAS.
//
//DTHAS is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 2 of the License, or 
//(at your option) any later version.
//
//DTHAS is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with DTHAS; If not, see <http://www.gnu.org/licenses/>.  
//===========================================================================

/*
#include	"proc_global.h"
#include	"proc_type.h"
#include	"proc_prototype.h"
#include	<stdio.h>


#include 	"linux/netfilter.h"  
#include 	"linux/init.h"  
#include 	"linux/module.h"  
#include 	"linux/netfilter_ipv4.h"  
#include 	"linux/ip.h"  
#include 	"linux/inet.h" 
*/

#include 	<linux/module.h>
#include 	<linux/init.h>
#include 	<linux/moduleparam.h>
#include 	<linux/netfilter.h>  
#include 	<linux/netfilter_ipv4.h>  
#include 	<linux/ip.h>  
#include 	<linux/inet.h> 


unsigned int my_hookfn(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{  
	struct iphdr *iph;  
	iph = ip_hdr(skb);  
  
	printk(KERN_INFO"src IP %pI4\n", &iph->saddr);

	iph->saddr = in_aton("8.8.8.8");  
  
	return NF_ACCEPT;  
}

void test(void)
{
	printk(KERN_INFO "hello world, test\n");
}
  
static struct nf_hook_ops nfho = {
	.hook = my_hookfn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
	//.owner = THIS_MODULE
};  
  
static int __init sknf_init(void)  
{  
	if (nf_register_hook(&nfho)) 
	{  
	        printk(KERN_ERR"nf_register_hook() failed\n");  
	        return -1;  
	}  
	return 0;  
}  
  
static void __exit sknf_exit(void)  
{  
	nf_unregister_hook(&nfho);  
}  
  
module_init(sknf_init);  
module_exit(sknf_exit);  
MODULE_AUTHOR("test");  
MODULE_LICENSE("GPL"); 



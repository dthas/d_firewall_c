//===========================================================================
// pre_routing.c
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

#include 	<linux/module.h>
#include 	<linux/init.h>
#include 	<linux/moduleparam.h>
#include 	<linux/netfilter.h>  
#include 	<linux/netfilter_ipv4.h>  
#include 	<linux/ip.h>  
#include 	<linux/inet.h> 


#include	"module_global.h"
#include	"module_type.h"
#include	"module_prototype.h"

static unsigned int change_src_ip(struct sk_buff *skb);

unsigned int pre_routing(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{  
	//change_src_ip(skb);
	
	//return print_info("pre",skb); 
	
	//return refuse_port("pre",skb); 
	
	return refuse_ip_port("pre",skb); 

	//return NF_ACCEPT;
}


unsigned int change_src_ip(struct sk_buff *skb)
{  
	struct iphdr *iph;  
	iph = ip_hdr(skb);  
  
	printk(KERN_INFO"pre::before::src IP %pI4\n", &iph->saddr);

	iph->saddr = in_aton("8.8.8.8");  

	printk(KERN_INFO"pre::after::src IP %pI4\n", &iph->saddr);
  
	return NF_ACCEPT;  
}


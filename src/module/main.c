//===========================================================================
// main.c
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

#include	"module_prototype.h"
#include	"module_global.h"



static struct nf_hook_ops nho_pre_routing;
static struct nf_hook_ops nho_post_routing;
static struct nf_hook_ops nho_local_in;
static struct nf_hook_ops nho_local_out;
static struct nf_hook_ops nho_forward;


 
static int __init dfirewall_init(void)  
{
	printk("======================hook_init()======================\n");

	struct nf_hook_ops *p_nho	= NULL;

	//----------------------------------------------------------------------
	//初始化 pre_routing
	//----------------------------------------------------------------------
	p_nho	= &nho_pre_routing;

	p_nho->hook	= pre_routing;
	p_nho->pf	= PF_INET;
	p_nho->hooknum	= NF_INET_PRE_ROUTING;
	p_nho->priority	= NF_IP_PRI_FILTER-1;
	
	if (nf_register_hook(p_nho)) 
	{  
	        printk(KERN_ERR"pre routing::nf_register_hook() failed\n");  
	        return -1;  
	}

	//----------------------------------------------------------------------
	//初始化 post_routing
	//----------------------------------------------------------------------
	p_nho	= &nho_post_routing;

	p_nho->hook	= post_routing;
	p_nho->pf	= PF_INET;
	p_nho->hooknum	= NF_INET_POST_ROUTING;
	p_nho->priority	= NF_IP_PRI_FILTER-1;
	
	if (nf_register_hook(p_nho)) 
	{  
	        printk(KERN_ERR"post routing::nf_register_hook() failed\n");  
	        return -1;  
	}  

	//----------------------------------------------------------------------
	//初始化 local_in
	//----------------------------------------------------------------------
	p_nho	= &nho_local_in;

	p_nho->hook	= local_in;
	p_nho->pf	= PF_INET;
	p_nho->hooknum	= NF_INET_LOCAL_IN;
	p_nho->priority	= NF_IP_PRI_FILTER-1;
	
	if (nf_register_hook(p_nho)) 
	{  
	        printk(KERN_ERR"local in::nf_register_hook() failed\n");  
	        return -1;  
	}

	//----------------------------------------------------------------------
	//初始化 local_out
	//----------------------------------------------------------------------
	p_nho	= &nho_local_out;

	p_nho->hook	= local_out;
	p_nho->pf	= PF_INET;
	p_nho->hooknum	= NF_INET_LOCAL_OUT;
	p_nho->priority	= NF_IP_PRI_FILTER-1;
	
	if (nf_register_hook(p_nho)) 
	{  
	        printk(KERN_ERR"local out::nf_register_hook() failed\n");  
	        return -1;  
	}  

	//----------------------------------------------------------------------
	//初始化 forward
	//----------------------------------------------------------------------
	p_nho	= &nho_forward;

	p_nho->hook	= forward;
	p_nho->pf	= PF_INET;
	p_nho->hooknum	= NF_INET_FORWARD;
	p_nho->priority	= NF_IP_PRI_FILTER-1;
	
	if (nf_register_hook(p_nho)) 
	{  
	        printk(KERN_ERR"forward::nf_register_hook() failed\n");  
	        return -1;  
	}  

	//----------------------------------------------------------------------
	//初始化 refuse_port
	//----------------------------------------------------------------------
	refuse_port_init();


	return 0;  
}  
  
static void __exit dfirewall_exit(void)  
{
	printk("======================hook_exit()======================\n");

	nf_unregister_hook(&nho_pre_routing);
	nf_unregister_hook(&nho_post_routing);
	nf_unregister_hook(&nho_local_in);
	nf_unregister_hook(&nho_local_out);
	nf_unregister_hook(&nho_forward);  
}  
  
module_init(dfirewall_init);  
module_exit(dfirewall_exit);  
MODULE_AUTHOR("dthas");  
MODULE_LICENSE("GPL"); 



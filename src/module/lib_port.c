//===========================================================================
// lib_port.c
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
#include 	<linux/tcp.h>
#include 	<linux/inet.h> 

#include	"module_prototype.h"


//=================================================================
// 通过端口过滤tcp数据包
//=================================================================
int refuse_port(char *type,struct sk_buff *skb)  
{  
    int retval = NF_ACCEPT;  
         
    struct iphdr *iph = ip_hdr(skb);    
    struct tcphdr *tcp = NULL;  
      
    //对于tcp数据包（udp的暂时不算）  
    if( iph->protocol == IPPROTO_TCP )  
    {  
        tcp = tcp_hdr(skb);	
  
        printk("%s: "  
                "%d.%d.%d.%d => %d.%d.%d.%d "  
                "%u -- %u\n",  
                type,  
                (iph->saddr&0x000000FF)>>0,  
                (iph->saddr&0x0000FF00)>>8,  
                (iph->saddr&0x00FF0000)>>16,  
                (iph->saddr&0xFF000000)>>24,  
                (iph->daddr&0x000000FF)>>0,  
                (iph->daddr&0x0000FF00)>>8,  
                (iph->daddr&0x00FF0000)>>16,  
                (iph->daddr&0xFF000000)>>24,  
                htons(tcp->source),  
                htons(tcp->dest)  
                );  
  
	
	switch(htons(tcp->dest))
	{
		//丢弃 80 , 1000, 10000 端口数据包
		case 80:
		case 1000:
		case 10000:
			retval 	= NF_DROP;
			break;
		default:
			retval	= NF_ACCEPT;
			break;
	}
    }  
  
    return retval;  
} 



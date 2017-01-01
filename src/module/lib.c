//===========================================================================
// lib.c
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

#define PORT 80 

//=================================================================
// 过滤 PORT 数据包
//=================================================================
int filter_http(char *type,struct sk_buff *pskb)  
{  
    int retval = NF_ACCEPT;  
    struct sk_buff *skb = pskb;  
      
    struct iphdr *iph = ip_hdr(skb);  // 获取ip头  
    struct tcphdr *tcp = NULL;  
    char *p = NULL;  
  
    // 解析TCP数据包  
    if( iph->protocol == IPPROTO_TCP )  
    {  
        tcp = tcp_hdr(skb);  
                p = (char*)(skb->data+iph->tot_len); // 注：sk_buff的data字段数据从ip头开始，不包括以太网数据帧  
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
  
	
        if( htons(tcp->dest) == PORT )    // 当目标端口为80，则丢弃  
        {  
            retval = NF_DROP;  
        } 	
    }  
  
    return retval;  
} 

//=================================================================
// 打印数据包信息
//=================================================================
int print_info(char *type,struct sk_buff *pskb)  
{  
    int retval = NF_ACCEPT;  
    struct sk_buff *skb = pskb;  
      
    struct iphdr *iph = ip_hdr(skb);  // 获取ip头  
    struct tcphdr *tcp = NULL;  
    char *p = NULL;  
  
    // 解析TCP数据包  
    if( iph->protocol == IPPROTO_TCP )  
    {  
        tcp = tcp_hdr(skb);  
                p = (char*)(skb->data+iph->tot_len); // 注：sk_buff的data字段数据从ip头开始，不包括以太网数据帧  
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
      }  
  
    return retval;  
}  

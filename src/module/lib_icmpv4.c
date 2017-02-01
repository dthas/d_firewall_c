//===========================================================================
// lib_icmpv4.c
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

#include 	<linux/icmp.h>   

#include	"module_global.h"
#include	"module_type.h"
#include	"module_ip_port.h"
#include	"module_prototype.h"
#include	"module_ipv4.h"
#include	"module_icmpv4.h"

/*
struct icmphdr {
  __u8		type;
  __u8		code;
  __sum16	checksum;
  union {
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
	__be32	gateway;
	struct {
		__be16	__unused;
		__be16	mtu;
	} frag;
  } un;
};
*/

//=================================================================
// 初始化 icmpv4_trans_info
//=================================================================
int icmpv4_trans_info(struct sk_buff *skb) 
{
	printk("======================icmpv4 trans info======================\n");

	//----------------------------------------------------------------------
	//获取icmpv4信息
	//----------------------------------------------------------------------
	struct icmphdr *icmpv4 = icmp_hdr(skb); 

	unsigned char type;
	unsigned char code;  

	type		= icmpv4->type;
	code		= icmpv4->code;

	printk("type: %d , code: %d\n",type, code);  

	return NF_ACCEPT; 	
}

//=================================================================
// 通过ip地址、端口过滤icmpv4数据包
//=================================================================
int icmpv4_modi_main(struct sk_buff *skb)  
{
	unsigned char type;
	unsigned char code; 

	type	= 12;
	//code	= 12

	//修改 type
	icmpv4_modi(ICMPV4_TYPE_MODI, type, skb);

	//修改 code
	//icmpv4_modi(ICMPV4_CODE_MODI, code, skb);

	icmpv4_prt_info(skb);

	return NF_ACCEPT;

}

//=================================================================
// 通过ip地址、端口过滤icmpv4数据包
//=================================================================
int icmpv4_modi(int type, unsigned char val, struct sk_buff *skb)  
{  
   	struct icmphdr *icmpv4 = icmp_hdr(skb);  
    	
	switch(type)
	{
		case ICMPV4_TYPE_MODI:
			icmpv4->type	= val;
			break;
		case ICMPV4_CODE_MODI:
			icmpv4->code	= val;
			break;
		default:
			return 0;
			break;
	}

	return 1;      	 
} 

//=================================================================
// 打印icmpv4的信息
//=================================================================
int icmpv4_prt_info(struct sk_buff *skb) 
{
	printk("======================icmpv4 info======================\n");

	//----------------------------------------------------------------------
	//获取icmpv4信息
	//----------------------------------------------------------------------
	struct icmphdr *icmpv4 = icmp_hdr(skb); 

	printk("type: %d , code: %d\n",icmpv4->type, icmpv4->code);	
}

//===========================================================================
// lib_tcp.c
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

#include 	<linux/fs.h>   
#include 	<asm/uaccess.h>   
#include 	<linux/mm.h>


#include	"module_global.h"
#include	"module_type.h"
#include	"module_ip_port.h"
#include	"module_prototype.h"
#include	"module_ipv4.h"
#include	"module_tcp.h"

/*
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};


//	The union cast uses a gcc extension to avoid aliasing problems
//  (union is compatible to any of its members)
//  This means this part of the code is -fstrict-aliasing safe now.
//
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
};
*/

//=================================================================
// 初始化 tcp_trans_info
//=================================================================
int tcp_trans_info(struct sk_buff *skb) 
{
	printk("======================tcp trans info======================\n");

	//----------------------------------------------------------------------
	//获取tcp信息
	//----------------------------------------------------------------------
	struct tcphdr *tcp = tcp_hdr(skb); 

	int src_port, dst_port;  

	src_port	= htons(tcp->source);
	dst_port	= htons(tcp->dest);

	printk("src port %u , dst port %u\n",src_port,dst_port);  

	return NF_ACCEPT; 	
}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int tcp_modi_main(struct sk_buff *skb)  
{
	unsigned int port;

	port	= 19213;

	//修改“源端口”
	tcp_modi(TYPE_TCP_SRC_PORT, port, skb);

	//修改“目的端口”
	//tcp_modi(TYPE_TCP_DST_PORT, port, skb);

	tcp_prt_info(skb);

	return NF_ACCEPT;

}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int tcp_modi(int type, unsigned int port, struct sk_buff *skb)  
{  
   	struct tcphdr *tcph = tcp_hdr(skb);   
    	
	switch(type)
	{
		case TYPE_TCP_SRC_PORT:
			tcph->source	= htons(port);
			break;
		case TYPE_TCP_DST_PORT:
			tcph->dest	= htons(port);
			break;
		default:
			return 0;
			break;
	}

	return 1;      	 
} 

//=================================================================
// 打印tcp的信息
//=================================================================
int tcp_prt_info(struct sk_buff *skb) 
{
	printk("======================tcp info======================\n");

	//----------------------------------------------------------------------
	//获取tcp信息
	//----------------------------------------------------------------------
	struct tcphdr *tcph = tcp_hdr(skb); 

	printk("src port %u , dst port %u\n",htons(tcph->source), htons(tcph->dest));	
}

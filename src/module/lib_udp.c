//===========================================================================
// lib_udp.c
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

#include 	<linux/udp.h>


#include	"module_global.h"
#include	"module_type.h"
#include	"module_ip_port.h"
#include	"module_prototype.h"
#include	"module_ipv4.h"
#include	"module_udp.h"

/*
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};
*/

//=================================================================
// 初始化 udp_trans_info
//=================================================================
int udp_trans_info(struct sk_buff *skb) 
{
	printk("======================udp trans info======================\n");

	//----------------------------------------------------------------------
	//获取udp信息
	//----------------------------------------------------------------------
	struct udphdr *udph = udp_hdr(skb); 

	int src_port, dst_port;  

	src_port	= htons(udph->source);
	dst_port	= htons(udph->dest);

	printk("src port %u , dst port %u\n",src_port,dst_port);  

	return NF_ACCEPT; 	
}

//=================================================================
// 通过ip地址、端口过滤udp数据包
//=================================================================
int udp_modi_main(struct sk_buff *skb)  
{
	unsigned int port;

	port	= 31112;

	//修改“源端口”
	//udp_modi(TYPE_UDP_SRC_PORT, port, skb);

	//修改“目的端口”
	udp_modi(TYPE_UDP_DST_PORT, port, skb);

	udp_prt_info(skb);

	return NF_ACCEPT;

}

//=================================================================
// 通过ip地址、端口过滤udp数据包
//=================================================================
int udp_modi(int type, unsigned int port, struct sk_buff *skb)  
{  
   	struct udphdr *udph = udp_hdr(skb);   
    	
	switch(type)
	{
		case TYPE_UDP_SRC_PORT:
			udph->source	= htons(port);
			break;
		case TYPE_UDP_DST_PORT:
			udph->dest	= htons(port);
			break;
		default:
			return 0;
			break;
	}

	return 1;      	 
} 

//=================================================================
// 打印udp的信息
//=================================================================
int udp_prt_info(struct sk_buff *skb) 
{
	printk("======================udp info======================\n");

	//----------------------------------------------------------------------
	//获取udp信息
	//----------------------------------------------------------------------
	struct udphdr *udph = udp_hdr(skb);   

	printk("src port %u , dst port %u\n",htons(udph->source), htons(udph->dest));	
}

//===========================================================================
// lib_arp.c
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

//#include 	<uapi/linux/if_arp.h> 
#include 	<linux/if_arp.h> 
#include 	<uapi/linux/if_ether.h>   


#include	"module_global.h"
#include	"module_type.h"
#include	"module_ip_port.h"
#include	"module_prototype.h"
#include	"module_ipv4.h"
#include	"module_tcp.h"
#include	"module_arp.h"

/*
//uapi/linux/if_ether.h:

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	// destination eth addr	
	unsigned char	h_source[ETH_ALEN];	// source ether addr	
	__be16		h_proto;		// packet type ID field	
} __attribute__((packed));
*/

static struct hwaddr src_mac;
static struct hwaddr dst_mac;
static unsigned short mac_type;
//=================================================================
// 初始化 tcp_trans_info
//=================================================================
int arp_trans_info(struct sk_buff *skb) 
{
	printk("======================arp trans info======================\n");

	//----------------------------------------------------------------------
	//获取arp信息
	//----------------------------------------------------------------------	
	struct ethhdr *mach = (struct ethhdr*)(skb->head + skb->mac_header);
	
	src_mac.addr1	= mach->h_source[0];
	src_mac.addr2	= mach->h_source[1];
	src_mac.addr3	= mach->h_source[2];
	src_mac.addr4	= mach->h_source[3];
	src_mac.addr5	= mach->h_source[4];
	src_mac.addr6	= mach->h_source[5];

	dst_mac.addr1	= mach->h_dest[0];
	dst_mac.addr2	= mach->h_dest[1];
	dst_mac.addr3	= mach->h_dest[2];
	dst_mac.addr4	= mach->h_dest[3];
	dst_mac.addr5	= mach->h_dest[4];
	dst_mac.addr6	= mach->h_dest[5];

	mac_type	= mach->h_proto;

	printk("source mac: %x:%x:%x:%x:%x:%x , dest mac: %x:%x:%x:%x:%x:%x, type: %x\n",  
		        src_mac.addr1,src_mac.addr2,src_mac.addr3,src_mac.addr4,src_mac.addr5,src_mac.addr6,  
		        dst_mac.addr1,dst_mac.addr2,dst_mac.addr3,dst_mac.addr4,dst_mac.addr5,dst_mac.addr6, mac_type); 

	return NF_ACCEPT; 	
}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int arp_modi_main(struct sk_buff *skb)  
{
	struct hwaddr mac;
	unsigned short mtype;

	mac.addr1	= 0x61;
	mac.addr2	= 0x62;
	mac.addr3	= 0x63;
	mac.addr4	= 0x64;
	mac.addr5	= 0x65;
	mac.addr6	= 0x66;

	//修改“源端口”
	//mac_modi(TYPE_SRC_MAC, &mac, skb);

	//修改“目的端口”
	mac_modi(TYPE_DST_MAC, &mac, skb);

	mac_prt_info(skb);

	return NF_ACCEPT;

}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int mac_modi(int type, struct hwaddr *mac, struct sk_buff *skb)  
{  
   	struct ethhdr *mach = (struct ethhdr*)(skb->head + skb->mac_header);
	    	
	switch(type)
	{

		case TYPE_SRC_MAC:
			mach->h_source[0]  	= mac->addr1;
			mach->h_source[1]	= mac->addr2;
			mach->h_source[2]	= mac->addr3;
			mach->h_source[3]	= mac->addr4;
			mach->h_source[4]	= mac->addr5;
			mach->h_source[5]	= mac->addr6;
			break;
		case TYPE_DST_MAC:
			mach->h_dest[0]  	= mac->addr1;
			mach->h_dest[1]		= mac->addr2;
			mach->h_dest[2]		= mac->addr3;
			mach->h_dest[3]		= mac->addr4;
			mach->h_dest[4]		= mac->addr5;
			mach->h_dest[5]		= mac->addr6;
			break;

		default:
			return 0;
			break;
	}

	return 1;       	 
} 

//=================================================================
// 打印ipv4的信息
//=================================================================
int mac_prt_info(struct sk_buff *skb) 
{
	printk("======================mac info======================\n");

	//----------------------------------------------------------------------
	//获取mac信息
	//----------------------------------------------------------------------

	struct ethhdr *mach = (struct ethhdr*)(skb->head + skb->mac_header);

	src_mac.addr1	= mach->h_source[0];
	src_mac.addr2	= mach->h_source[1];
	src_mac.addr3	= mach->h_source[2];
	src_mac.addr4	= mach->h_source[3];
	src_mac.addr5	= mach->h_source[4];
	src_mac.addr6	= mach->h_source[5];

	dst_mac.addr1	= mach->h_dest[0];
	dst_mac.addr2	= mach->h_dest[1];
	dst_mac.addr3	= mach->h_dest[2];
	dst_mac.addr4	= mach->h_dest[3];
	dst_mac.addr5	= mach->h_dest[4];
	dst_mac.addr6	= mach->h_dest[5];

	mac_type	= mach->h_proto;

	printk("source mac: %x:%x:%x:%x:%x:%x , dest mac: %x:%x:%x:%x:%x:%x, type: %x\n",  
		        src_mac.addr1,src_mac.addr2,src_mac.addr3,src_mac.addr4,src_mac.addr5,src_mac.addr6,  
		        dst_mac.addr1,dst_mac.addr2,dst_mac.addr3,dst_mac.addr4,dst_mac.addr5,dst_mac.addr6, mac_type); 
}

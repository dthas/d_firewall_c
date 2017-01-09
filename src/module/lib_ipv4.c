//===========================================================================
// lib_ipv4.c
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

/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	//The options start here. 
}
*/

static struct iaddr src_ip;
static struct iaddr dst_ip;

//=================================================================
// 初始化 ipv4_trans_info
//=================================================================
int ipv4_trans_info(struct sk_buff *skb) 
{
	printk("======================ipv4 trans info======================\n");

	//----------------------------------------------------------------------
	//获取ip信息
	//----------------------------------------------------------------------
	struct iphdr *iph = ip_hdr(skb);  

	src_ip.addr1	= (iph->saddr&0x000000FF)>>0;
	src_ip.addr2	= (iph->saddr&0x0000FF00)>>8;
	src_ip.addr3	= (iph->saddr&0x00FF0000)>>16;
	src_ip.addr4	= (iph->saddr&0xFF000000)>>24;

	dst_ip.addr1	= (iph->daddr&0x000000FF)>>0;
	dst_ip.addr2	= (iph->daddr&0x0000FF00)>>8;
	dst_ip.addr3	= (iph->daddr&0x00FF0000)>>16;
	dst_ip.addr4	= (iph->daddr&0xFF000000)>>24;

	printk("source ip: %d.%d.%d.%d , dest ip: %d.%d.%d.%d\n",  
		        src_ip.addr1,src_ip.addr2,src_ip.addr3,src_ip.addr4,  
		        dst_ip.addr1,dst_ip.addr2,dst_ip.addr3,dst_ip.addr4);

	return NF_ACCEPT; 	
}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int ipv4_modi_main(struct sk_buff *skb)  
{
	struct iaddr mod_ip;

	mod_ip.addr1	= 90;
	mod_ip.addr2	= 91;
	mod_ip.addr3	= 92;
	mod_ip.addr4	= 93;

	//修改“源ip”
	//ipv4_modi(TYPE_SRC_IP, &mod_ip, skb);

	//修改“目的ip”
	//ipv4_modi(TYPE_DST_IP, &mod_ip, skb);

	ipv4_prt_info(skb);

	return NF_ACCEPT;

}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int ipv4_modi(int type, struct iaddr *ip, struct sk_buff *skb)  
{  
   	struct iphdr *iph = ip_hdr(skb);    
    	
	switch(type)
	{
		case TYPE_SRC_IP:
			iph->saddr = (ip->addr1) | ((ip->addr2)<<8) | ((ip->addr3)<<16) | ((ip->addr4)<<24);
			break;
		case TYPE_DST_IP:
			iph->daddr = (ip->addr1) | ((ip->addr2)<<8) | ((ip->addr3)<<16) | ((ip->addr4)<<24);
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
int ipv4_prt_info(struct sk_buff *skb) 
{
	printk("======================ipv4 info======================\n");

	//----------------------------------------------------------------------
	//获取ip信息
	//----------------------------------------------------------------------
	struct iphdr *iph = ip_hdr(skb);  

	src_ip.addr1	= (iph->saddr&0x000000FF)>>0;
	src_ip.addr2	= (iph->saddr&0x0000FF00)>>8;
	src_ip.addr3	= (iph->saddr&0x00FF0000)>>16;
	src_ip.addr4	= (iph->saddr&0xFF000000)>>24;

	dst_ip.addr1	= (iph->daddr&0x000000FF)>>0;
	dst_ip.addr2	= (iph->daddr&0x0000FF00)>>8;
	dst_ip.addr3	= (iph->daddr&0x00FF0000)>>16;
	dst_ip.addr4	= (iph->daddr&0xFF000000)>>24;

	printk("source ip: %d.%d.%d.%d , dest ip: %d.%d.%d.%d\n",  
		        src_ip.addr1,src_ip.addr2,src_ip.addr3,src_ip.addr4,  
		        dst_ip.addr1,dst_ip.addr2,dst_ip.addr3,dst_ip.addr4);	
}


//===========================================================================
// add_ipv4_header
//===========================================================================
void 	add_ipv4_header(struct sk_buff *skb, struct iaddr src_ip, unsigned char ttl, struct iaddr dst_ip, unsigned char protocol, unsigned char tos, unsigned short total_len, unsigned short offset, unsigned char flag)
{
	//struct s_ipv4_header * iph = (struct s_ipv4_header *)(&(pkg->buffer[FRAME_HEADER_LENGTH]));
	struct s_ipv4_header * iph = (struct s_ipv4_header *)ip_hdr(skb);

	iph->version_len	= (IP_VERSION_4 << 4) | IP_HEADER_LEN_IN_BYTE;
	iph->tos		= tos;
	iph->length		= total_len;
	iph->iden		= 0;

	//unsigned short tmp_flag_offset	= (flag << 13) | offset;
	iph->flag_offset	= big_little_16((flag << 13) | offset) ;

	iph->ttl		= ttl;
	iph->protocol		= protocol;
	iph->checksum		= 0;

	iph->src_ip.addr1	= src_ip.addr1; 
	iph->src_ip.addr2	= src_ip.addr2; 
	iph->src_ip.addr3	= src_ip.addr3; 
	iph->src_ip.addr4	= src_ip.addr4; 

	iph->dst_ip.addr1	= dst_ip.addr1;
	iph->dst_ip.addr2	= dst_ip.addr2;
	iph->dst_ip.addr3	= dst_ip.addr3;
	iph->dst_ip.addr4	= dst_ip.addr4;

	iph->checksum		= makechksum(iph,IPV4_HEADER_LENGTH);
}


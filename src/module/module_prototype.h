//===========================================================================
// module_prototype.h
//
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Originally by ZhaoFeng Liang <zhf.liang@hotmail.com>
//
//This file is part of DTHAS_FIREWALL.
//
//DTHAS_TLS is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 2 of the License, or 
//(at your option) any later version.
//
//DTHAS_TLS is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with DTHAS_TLS; If not, see <http://www.gnu.org/licenses/>.  
//===========================================================================

#ifndef	_MODULE_PROTOTYPE_H_
#define	_MODULE_PROTOTYPE_H_

unsigned int pre_routing(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *));
unsigned int post_routing(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *));
unsigned int local_in(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *));
unsigned int local_out(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *));
unsigned int forward(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *));

//lib_port.c
int 	refuse_port(char *type,struct sk_buff *pskb);
void	refuse_port_init(void);
int 	print_info(char *type,struct sk_buff *pskb);

//lib_ip_port.c
void	refuse_ip_port_init(void);
int 	refuse_ip_port(char *type,struct sk_buff *pskb);

//lib.c
void 	str_copy(char *dest, char *src);
void 	str_cpy(char *dest, char *src, int len);
int 	str_len(char *buf);
int 	squ(int num, int ind);
int	s2i(char * str);
void 	s2ip(struct iaddr * ip, char *buf);
int 	chk_src_dest_ip(struct iaddr *src_ip, struct iaddr *dest_ip);
void	empty_buf(unsigned int start_addr, int size_in_byte);
void	kreadf(char *filename, char *data, int len);
unsigned short 	makechksum(unsigned char *pkg, unsigned short num);
unsigned short 	big_little_16(unsigned short val);
unsigned int 	big_little_32(unsigned int val);
unsigned short 	little_big_16(unsigned short val);
unsigned int 	little_big_32(unsigned int val);

//lib_ipv4.c
int ipv4_trans_info(struct sk_buff *skb);
int ipv4_modi(int type, struct iaddr *ip, struct sk_buff *skb);
int ipv4_modi_main(struct sk_buff *skb);
int ipv4_prt_info(struct sk_buff *skb);
void 	add_ipv4_header(struct sk_buff *skb, struct iaddr src_ip, unsigned char ttl, struct iaddr dst_ip, unsigned char protocol, unsigned char tos, unsigned short total_len, unsigned short offset, unsigned char flag);


//lib_tcp.c
int tcp_trans_info(struct sk_buff *skb);
int tcp_modi_main(struct sk_buff *skb) ;
int tcp_modi(int type, unsigned int port, struct sk_buff *skb);
int tcp_prt_info(struct sk_buff *skb);
int tcp_data_hack(struct sk_buff *skb);
void 	add_tcp_header(struct sk_buff *skb, struct iaddr src_ip, unsigned short tcp_len, struct iaddr dst_ip, unsigned char protocol,unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack, unsigned char header_len, unsigned char ctrl_bit, unsigned short winsize, unsigned short upointer);

//lib_arp.c
int arp_trans_info(struct sk_buff *skb);
int arp_modi_main(struct sk_buff *skb) ;
int mac_modi(int type, struct hwaddr *mac, struct sk_buff *skb);
int mac_prt_info(struct sk_buff *skb);
void 	add_frame_header(struct sk_buff *skb, unsigned short type, struct hwaddr dst_mac, struct hwaddr src_mac);

//lib_udp.c
int udp_trans_info(struct sk_buff *skb);
int udp_modi_main(struct sk_buff *skb) ;
int udp_modi(int type, unsigned int port, struct sk_buff *skb);
int udp_prt_info(struct sk_buff *skb);

//lib_icmpv4.c
int icmpv4_trans_info(struct sk_buff *skb);
int icmpv4_modi_main(struct sk_buff *skb) ;
int icmpv4_modi(int type, unsigned char val, struct sk_buff *skb);
int icmpv4_prt_info(struct sk_buff *skb);

#endif

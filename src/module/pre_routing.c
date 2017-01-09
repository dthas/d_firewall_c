//===========================================================================
// pre_routing.c
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
#include 	<linux/inet.h> 

#include 	<linux/if_arp.h> 
#include 	<uapi/linux/if_ether.h> 


#include	"module_global.h"
#include	"module_type.h"
#include	"module_prototype.h"

/*
<uapi/linux/in.h>

enum {
  IPPROTO_IP = 0,		// Dummy protocol for TCP		
  IPPROTO_ICMP = 1,		// Internet Control Message Protocol	
  IPPROTO_IGMP = 2,		// Internet Group Management Protocol	
  IPPROTO_IPIP = 4,		// IPIP tunnels (older KA9Q tunnels use 94) 
  IPPROTO_TCP = 6,		// Transmission Control Protocol	
  IPPROTO_EGP = 8,		// Exterior Gateway Protocol		
  IPPROTO_PUP = 12,		// PUP protocol				
  IPPROTO_UDP = 17,		// User Datagram Protocol		
  IPPROTO_IDP = 22,		// XNS IDP protocol			
  IPPROTO_TP = 29,		// SO Transport Protocol Class 4	
  IPPROTO_DCCP = 33,		// Datagram Congestion Control Protocol 
  IPPROTO_IPV6 = 41,		// IPv6-in-IPv4 tunnelling		
  IPPROTO_RSVP = 46,		// RSVP Protocol			
  IPPROTO_GRE = 47,		// Cisco GRE tunnels (rfc 1701,1702)	
  IPPROTO_ESP = 50,		// Encapsulation Security Payload protocol 
  IPPROTO_AH = 51,		// Authentication Header protocol	
  IPPROTO_MTP = 92,		// Multicast Transport Protocol		
  IPPROTO_BEETPH = 94,		// IP option pseudo header for BEET	
  IPPROTO_ENCAP = 98,		// Encapsulation Header			
  IPPROTO_PIM = 103,		// Protocol Independent Multicast	
  IPPROTO_COMP = 108,		// Compression Header Protocol		
  IPPROTO_SCTP = 132,		// Stream Control Transport Protocol	
  IPPROTO_UDPLITE = 136,	// UDP-Lite (RFC 3828)			
  IPPROTO_MPLS = 137,		// MPLS in IP (RFC 4023)		
  IPPROTO_RAW = 255,		// Raw IP packets			
  IPPROTO_MAX
};
*/

static unsigned int change_src_ip(struct sk_buff *skb);

unsigned int pre_routing(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{  
	struct ethhdr *mach 		= (struct ethhdr*)(skb->head + skb->mac_header);
	struct iphdr *iph 		= ip_hdr(skb);
	unsigned short arp_protocol	= htons(mach->h_proto);

	switch(arp_protocol)
	{
		case ETH_P_ARP:
		case ETH_P_RARP:
			//return arp_trans_info(skb); 

			//return arp_modi_main(skb); 
			break;
		case ETH_P_IPV6:
			break;
		case ETH_P_IP:
			switch(iph->protocol)
			{
				case IPPROTO_ICMP:
					//return icmpv4_trans_info(skb); 

					//return icmpv4_modi_main(skb);
					break;
				case IPPROTO_TCP:
					//return tcp_trans_info(skb); 

					//return tcp_modi_main(skb);

					//在tcp数据包里修改mac地址
					//return arp_modi_main(skb);

					//修改tcp数据包内容
					return tcp_data_hack(skb);
					break;
				case IPPROTO_UDP:
					//return udp_trans_info(skb); 

					//return udp_modi_main(skb);
					break;
				default:
					return NF_ACCEPT;
					break;
			}
		default:
			return NF_ACCEPT;
	}


	//change_src_ip(skb);
	
	//return print_info("pre",skb); 
	
	//return refuse_port("pre",skb); 
	
	//return refuse_ip_port("pre",skb);

	//return ipv4_trans_info(skb); 

	//return ipv4_modi_main(skb);	

	//return NF_ACCEPT;
}


unsigned int change_src_ip(struct sk_buff *skb)
{  
	struct iphdr *iph;  
	iph = ip_hdr(skb);  
  
	printk(KERN_INFO"pre::before::src IP %pI4\n", &iph->saddr);

	iph->saddr = in_aton("8.8.8.8");  

	printk(KERN_INFO"pre::after::src IP %pI4\n", &iph->saddr);
  
	return NF_ACCEPT;  
}


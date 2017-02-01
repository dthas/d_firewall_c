//===========================================================================
// module_tcp.h
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

#ifndef	_MODULE_TCP_H_
#define	_MODULE_TCP_H_

#define	TYPE_TCP_SRC_PORT	1
#define	TYPE_TCP_DST_PORT	2

#define	TMP_TCP_PACKET_LEN	4096


#define TCP_HEADER_LENGTH		20
#define TCP_HEADER_LENGTH_IN_DWORD	5		//5*4=20
#define PTCP_HEADER_LENGTH		12


/*
#define FIN_BIT				0x1
#define SYN_BIT				0x2
#define PST_BIT				0x4
#define PSH_BIT				0x8
#define ACK_BIT				0x10
#define URG_BIT				0x20
*/

#define FIN_BIT				0x80
#define SYN_BIT				0x40
#define PST_BIT				0x20
#define PSH_BIT				0x10
#define ACK_BIT				0x8
#define URG_BIT				0x4

struct s_tcp_header
{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char  header_len;
	unsigned char  ctrl_bit;
	unsigned short winsize;
	unsigned short checksum;
	unsigned short upointer;		
};

struct s_tcp_header_1
{
	unsigned short	source;
	unsigned short	dest;
	unsigned int	seq;
	unsigned int	ack_seq;
	unsigned short	res1:4,
			doff:4,
			fin:1,
			syn:1,
			rst:1,
			psh:1,
			ack:1,
			urg:1,
			ece:1,
			cwr:1;
	unsigned short	window;
	unsigned short	check;
	unsigned short	urg_ptr;		
};

struct s_ptcp_header
{
	struct iaddr src_ip;
	struct iaddr dst_ip;
	unsigned char zero;
	unsigned char protocol;
	unsigned short tcp_len;	
};

struct s_g_tcp_header
{
	struct s_ptcp_header p;			//tcp伪首部
	struct s_tcp_header_1  t;		//tcp首部
};



#endif

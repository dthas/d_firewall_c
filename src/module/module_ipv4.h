//===========================================================================
// module_ipv4.h
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

#ifndef	_MODULE_IPV4_H_
#define	_MODULE_IPV4_H_

#define	TYPE_SRC_IP	1
#define	TYPE_DST_IP	2

#define	IP_VERSION_4		0x4
#define	IP_HEADER_LEN_IN_BYTE	0x5	//5 * 4 = 20 BYTES

#define IPV4_HEADER_LENGTH	20

struct s_ipv4_header
{
	unsigned char version_len;
	unsigned char tos;
	unsigned short length;
	unsigned short iden;
	unsigned short flag_offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	struct iaddr src_ip;
	struct iaddr dst_ip;
};





#endif

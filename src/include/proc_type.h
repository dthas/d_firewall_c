//===========================================================================
// proc_type.h
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

#ifndef	_PROC_TYPE_H_
#define	_PROC_TYPE_H_

#define	PUBLIC		
#define	PRIVATE	static

#define	NULL	'\0'


typedef	unsigned long long	u64;
typedef	unsigned int		u32;
typedef	unsigned short		u16;
typedef	unsigned char		u8;

typedef	long long		s64;
typedef	int			s32;
typedef	short			s16;
typedef	char			s8;

struct iaddr
{
	u8	addr1;
	u8	addr2;
	u8	addr3;
	u8	addr4;
};


#endif

//===========================================================================
// lib.c
//
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Originally by ZhaoFeng Liang <zhf.liang@hotmail.com>
//
//This file is part of DTHAS_TLS.
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

#include	"proc_type.h"
#include	"proc_prototype.h"

PUBLIC 	void 	rev_256(u8 *buf)
{
	s32 i;
	u8 arr_temp[256];

	strcpy_1(arr_temp, buf, 256);

	for(i=0; i<256; i++)
	{
		buf[255-i]	= arr_temp[i];
	}
}

PUBLIC 	u16 	little_big_16(u16 val)
{
	u16 t_val = val;
	
	return(((val<<8)|(t_val>>8)));
}


PUBLIC 	void 	little_big_32(u32 * val)
{
	u8	a = (*val)>>24;
	u8	b = (*val)>>16;
	u8	c = (*val)>>8;
	u8	d = *val;
		

	u8* 	p = val;

	p[3]	= d;
	p[2]	= c;
	p[1]	= b;
	p[0]	= a;

	//printf(" a=%x,b=%x,c=%x,d=%x,e=%x,f=%x,g=%x,h=%x\n\n",a,b,c,d,e,f,g,h);
	
	//return ((h<<56) | (g<<48) | (f<<40) | (e<<32) | (d<<24) | (c<<16) | (b<<8) | a);
}

PUBLIC 	void 	little_big_64(u64 * val)
{
	u8	a = (*val)>>56;
	u8	b = (*val)>>48;
	u8	c = (*val)>>40;
	u8	d = (*val)>>32;
	u8	e = (*val)>>24;
	u8	f = (*val)>>16;
	u8	g = (*val)>>8;
	u8	h = (*val) & 0xff;	

	u8* 	p = val;

	p[7]	= h;
	p[6]	= g;
	p[5]	= f;
	p[4]	= e;
	p[3]	= d;
	p[2]	= c;
	p[1]	= b;
	p[0]	= a;

	//printf(" a=%x,b=%x,c=%x,d=%x,e=%x,f=%x,g=%x,h=%x\n\n",a,b,c,d,e,f,g,h);
	
	//return ((h<<56) | (g<<48) | (f<<40) | (e<<32) | (d<<24) | (c<<16) | (b<<8) | a);
}

PUBLIC 	void 	little_big_128(u64 * low_byte_val)
{
	u64 * high_byte_val	= low_byte_val + 1;

	little_big_64(low_byte_val);
	little_big_64(high_byte_val);

	u64	temp_val	= *low_byte_val;

	*low_byte_val		= *high_byte_val;
	*high_byte_val		= temp_val;
}

PUBLIC 	void 	memset_u64(u64* buf, u64 ch, s32 size)
{
	s32 i;

	for(i=0; i<size; i++)
	{
		buf[i]	= ch;
	}
}

PUBLIC 	void 	memset_u32(u32* buf, u32 ch, s32 size)
{
	s32 i;

	for(i=0; i<size; i++)
	{
		buf[i]	= ch;
	}
}

PUBLIC 	void 	memset_u8(u8* buf, u8 ch, s32 size)
{
	s32 i;

	for(i=0; i<size; i++)
	{
		buf[i]	= ch;
	}
}

PUBLIC 	u8 	s2i(u8 ch)
{
	u8 res;

	res	= 0;
	
	switch(ch)
	{
		case	48:
			res	= 0x0;
			break;
		case	49:
			res	= 0x1;
			break;
		case	50:
			res	= 0x2;
			break;
		case	51:
			res	= 0x3;
			break;
		case	52:
			res	= 0x4;
			break;
		case	53:
			res	= 0x5;
			break;
		case	54:
			res	= 0x6;
			break;
		case	55:
			res	= 0x7;
			break;
		case	56:
			res	= 0x8;
			break;
		case	57:
			res	= 0x9;
			break;

		case	65:
		case 	97:
			res	= 0xa;
			break;
		case	66:
		case	98:
			res	= 0xb;
			break;
		case	67:
		case	99:
			res	= 0xc;
			break;
		case	68:
		case	100:
			res	= 0xd;
			break;
		case	69:
		case	101:
			res	= 0xe;
			break;
		case	70:
		case	102:
			res	= 0xf;
			break;
		default:
			printf("s2i::wrong(%02x)\n", ch);
			break;
	}

	return res;
}

PUBLIC	u64 	pow(u64 a, u64 b)
{
	s32 i;
	u64 t = 1;
	for(i=0; i<b; i++)
	{
		t	*= a;
	}
	return t;
}

PUBLIC	u8*	lsb(u8* dst, s32 dst_len, s32 req_len)
{
	if(dst_len < req_len)
	{
		printf("error::lsb:: dst_len(%d) < req_len(%d)\n", dst_len, req_len);
		exit(0);
	}

	u8	*p	= &dst[dst_len - req_len];

	return p;
}

PUBLIC	u8*	msb(u8* dst, s32 dst_len, s32 req_len)
{
	if(dst_len < req_len)
	{
		printf("error::lsb:: dst_len(%d) < req_len(%d)\n", dst_len, req_len);
		exit(0);
	}

	u8	*p	= dst;

	return p;
}

PUBLIC	s32	beq(s32 a, s32 b, s32 c)
{
	s32 i, j;
	
	i	= (a * b) / c;
	j	= (a * b) % c;

	if(j)
	{
		i++;
	}

	return i;
}

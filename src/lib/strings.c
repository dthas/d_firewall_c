//===========================================================================
// strings.c
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

#include "proc_global.h"
#include "proc_type.h"


PUBLIC 	void strcpy_1(char *dest, char *src, s32 len)
{
	s32 i;

	for(i=0; i<len; i++)
	{
		*dest++ = *src++;
	}	
}


PUBLIC 	s8 strcmp_1(char *dest, char *src)
{
	s32	lend = strlen(dest);
	s32	lens = strlen(src);

	if(lend != lens)
	{
		return FALSE;
	}

	for(; lend > 0; lend--)
	{
		if(*dest++ != *src++)
		{
			break;
		}		
	}

	if(lend == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

PUBLIC 	s8 strcmp_2(char *dest, char *src, s32 lend)
{
	for(; lend > 0; lend--)
	{
		if(*dest++ != *src++)
		{
			break;
		}		
	}

	if(lend == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

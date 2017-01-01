//===========================================================================
// main.c
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

#include	"proc_global.h"
#include	"proc_type.h"
#include	"proc_prototype.h"
#include	<stdio.h>


extern test();

PUBLIC	int	main(int argc, char*argv[])
{
	
	printf("--start proc--,%d, %s\n",argc, argv[1]);

	sys_init_module(test);

	sys_delete_module(test);

	//module_init(test);

	//module_exit(test);

	printf("--end proc--\n");
	
	
	return 0;
}

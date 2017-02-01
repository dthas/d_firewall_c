//===========================================================================
// module_ip_port.h
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

#ifndef	_MODULE_IP_PORT_H_
#define	_MODULE_IP_PORT_H_

#define	NR_REFUSE_IP_PORT 65535

#define	IP_STATE_1	1
#define	IP_STATE_2	2
#define	IP_STATE_3	3
#define	IP_STATE_99	99

struct ip_port
{
	struct iaddr ip;
	int port;
};






#endif

//===========================================================================
// lib_ip_port.c
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

static struct ip_port arr_refuse_ip_port[NR_REFUSE_IP_PORT];
//static int *p_refuse_ip_port;

//=================================================================
// 初始化 refuse port
//=================================================================
void refuse_ip_port_init()  
{
	printk("======================init refuse ip port[]======================\n");

	int i,j,k,m, start, end;
	int state;
	//----------------------------------------------------------------------
	//初始化 refuse port[]
	//----------------------------------------------------------------------
	
	for(i=0;i<NR_REFUSE_IP_PORT;i++)
	{
		arr_refuse_ip_port[i].ip.addr1	= NULL;
		arr_refuse_ip_port[i].ip.addr2	= NULL;
		arr_refuse_ip_port[i].ip.addr3	= NULL;
		arr_refuse_ip_port[i].ip.addr4	= NULL;

		arr_refuse_ip_port[i].port	= NULL;
	}
	
	//----------------------------------------------------------------------
	//将refuse_ip_port.config内容读入 r_buf[]
	//
	//注意：
	//	这是内核读文件
	//----------------------------------------------------------------------
	char r_buf[NR_CHAR_FILE];
	char r_line[NR_CHAR_LINE];
	char r_ip[16];
	char r_port[16];
	int  i_len;

	mm_segment_t old_fs;
	loff_t pos; 
	struct file *fp_r = NULL;
	
	for(j=0;j<NR_CHAR_FILE;j++)
	{
		r_buf[j]	= NULL;
	}


	fp_r = filp_open("config/refuse_ip_port.config", O_RDONLY,0);	
		
	old_fs	= get_fs();
  	set_fs(KERNEL_DS);  
  	pos	= 0;
	vfs_read(fp_r,r_buf,sizeof(r_buf),&pos);
	set_fs(old_fs);

	filp_close(fp_r,NULL);


	
	//----------------------------------------------------------------------
	//将refuse_port.config内容读入 arr_refuse_ip_port[]
	//----------------------------------------------------------------------
	i 	= 0;
	j 	= 0;
	m	= 0;
	unsigned char *q;

	while (j<NR_CHAR_FILE)                                   
	{   		
		r_line[m]	= r_buf[j];
		m++;
		j++;
		
		if(r_line[m-1] == 0xa)	//找到 : （换行符）
		{
			state		= IP_STATE_1;
			
			start 	= 0;
			end 	= 0;

			for(start=0; start<m; start++)
			{
				switch(r_line[start])
				{
					case 0x20:	//空格
						continue;
						break;
					case 0x9:	//tab
						continue;
						break;
					case 0x3a:	//冒号
						r_ip[end]	= NULL;
						end		= 0;

						state		= IP_STATE_2;
	
						//跳过冒号
						start++;
						break;
					case 0xa:	//换行符
						r_port[end]	= NULL;
						end		= 0;

						state		= IP_STATE_3;
						break;
					default:
						break;
				}

				//for test
				//printk("state = %d:\n", state);

				switch(state)
				{
					case IP_STATE_1:
						r_ip[end]	= r_line[start];
						end++;
						break;
					case IP_STATE_2:
						r_port[end]	= r_line[start];
						end++;
						break;
					case IP_STATE_3:
						//-----------------------------------------------------
						// ip 处理
						//-----------------------------------------------------
						i_len 	= str_len(r_ip);

						//for test
						//printk("i_len=%d, r_ip=%s, r_port=%s\n",i_len, r_ip, r_port);

						char r_tmp[4];
						int x,y,z;

						q = (unsigned char *)(&(arr_refuse_ip_port[i].ip));

						for(x=0,y=0;x<=i_len;x++)
						{
							if(r_ip[x] == 0x2e)
							{
								r_tmp[y]	= NULL;
								y		= 0;

								*q = s2i(r_tmp);

								//for test
								//printk("	s2ip::i_len=%d, y=%d, r_tmp=%s, *q=%d\n",i_len, y, r_tmp, *q);
								
								q++;								
							}
							else if(r_ip[x] == NULL)
							{
								r_tmp[y]	= NULL;

								*q = s2i(r_tmp);

								//for test
								//printk("	s2ip::i_len=%d, y=%d, r_tmp=%s, *q=%d\n",i_len, y, r_tmp, *q);
							}
							else
							{
								r_tmp[y]	= r_ip[x];
								y++;
							}
						}

						//-----------------------------------------------------------
						//port的处理
						//-----------------------------------------------------------
						arr_refuse_ip_port[i].port = s2i(r_port);
						
						break;
					
					default:
						break;
				}

				if(state == IP_STATE_3)
				{
					state		= IP_STATE_1;
				}				
			}

			//for test
			//printk("(s)unchange line = %s",r_line);
			//printk("(i)  change ip = %d.%d.%d.%d, port = %d\n\n",arr_refuse_ip_port[i].ip.addr1,arr_refuse_ip_port[i].ip.addr2,arr_refuse_ip_port[i].ip.addr3,arr_refuse_ip_port[i].ip.addr4, arr_refuse_ip_port[i].port);

			m	= 0;
			i++;
		}
	}	

	//----------------------------------------------------------------------
	//测试打印 refuse port[]
	//----------------------------------------------------------------------
	for(j=0;j<i;j++)
	{
		printk("refuse_ip_port[%d] = %d.%d.%d.%d::%d\n",j,arr_refuse_ip_port[j].ip.addr1,arr_refuse_ip_port[j].ip.addr2,arr_refuse_ip_port[j].ip.addr3,arr_refuse_ip_port[j].ip.addr4, arr_refuse_ip_port[j].port);
	}
	
}

//=================================================================
// 通过ip地址、端口过滤tcp数据包
//=================================================================
int refuse_ip_port(char *type,struct sk_buff *skb)  
{  
   	int retval = NF_ACCEPT;  
         
    	struct iphdr *iph = ip_hdr(skb);    
    	struct tcphdr *tcp = NULL;  

    	struct iaddr src_ip;
	struct iaddr dst_ip;

	int src_port, dst_port;
      
	//对于tcp数据包（udp的暂时不算）  
	if( iph->protocol == IPPROTO_TCP )  
	{  
		tcp = tcp_hdr(skb);

		src_ip.addr1	= (iph->saddr&0x000000FF)>>0;
		src_ip.addr2	= (iph->saddr&0x0000FF00)>>8;
		src_ip.addr3	= (iph->saddr&0x00FF0000)>>16;
		src_ip.addr4	= (iph->saddr&0xFF000000)>>24;

		dst_ip.addr1	= (iph->daddr&0x000000FF)>>0;
		dst_ip.addr2	= (iph->daddr&0x0000FF00)>>8;
		dst_ip.addr3	= (iph->daddr&0x00FF0000)>>16;
		dst_ip.addr4	= (iph->daddr&0xFF000000)>>24;
			
		src_port	= htons(tcp->source);
		dst_port	= htons(tcp->dest);
	  
		printk("%s: %d.%d.%d.%d => %d.%d.%d.%d %u -- %u\n",type,  
		        src_ip.addr1,src_ip.addr2,src_ip.addr3,src_ip.addr4,  
		        dst_ip.addr1,dst_ip.addr2,dst_ip.addr3,dst_ip.addr4,src_port,dst_port  
		        );  
	  
		int i;
		while(arr_refuse_ip_port[i].port)
		{
			if(chk_src_dest_ip(&(arr_refuse_ip_port[i].ip), &dst_ip))
			{
				if(arr_refuse_ip_port[i].port == dst_port)
				{
					retval 	= NF_DROP;
					break;		
				}
			}	
			i++;
		}	
	}  
	  
	return retval;  
} 



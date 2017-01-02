//===========================================================================
// lib_port.c
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

#include	"module_prototype.h"
#include	"module_global.h"


static int arr_refuse_port[NR_REFUSE_PORT];
static int *p_refuse_port;

//=================================================================
// 初始化 refuse port
//=================================================================
void refuse_port_init()  
{
	printk("======================init refuse port[]======================\n");

	//----------------------------------------------------------------------
	//初始化 refuse port[]
	//----------------------------------------------------------------------
	int i,j,k;
	for(i=0;i<NR_REFUSE_PORT;i++)
	{
		arr_refuse_port[i]	= NULL;
	}
	p_refuse_port	= &arr_refuse_port;


	//----------------------------------------------------------------------
	//将refuse_port.config内容读入 r_buf[]
	//
	//注意：
	//	这是内核读文件
	//----------------------------------------------------------------------
	char r_buf[NR_CHAR_FILE];

	mm_segment_t old_fs;
	loff_t pos; 
	struct file *fp_r = NULL;
	
	for(j=0;j<NR_CHAR_FILE;j++)
	{
		r_buf[j]	= NULL;
	}


	fp_r = filp_open("config/refuse_port.config", O_RDONLY,0);	
		
	old_fs	= get_fs();
  	set_fs(KERNEL_DS);  
  	pos	= 0;
	vfs_read(fp_r,r_buf,sizeof(r_buf),&pos);
	set_fs(old_fs);

	filp_close(fp_r,NULL);


	
	//----------------------------------------------------------------------
	//将refuse_port.config内容读入 p_refuse_port[]
	//----------------------------------------------------------------------
	j=0;
	while (j<NR_CHAR_FILE)                                   
	{   
		if(r_buf[j] == 0xa)
		{
			//将换行符转换为NULL，方便后面的string函数处理
			r_buf[j]	= NULL;
		}
		j++;
	}

	i = 0;
	j = 0;
	k = 0;
	while (j<NR_CHAR_FILE)                                   
	{   
		//找到 = （等号）
		if(r_buf[j] == 0x3d)
		{
			//k为端口字符串的长度（如：1001，k=4）
			k = str_len(&r_buf[j+1+1]);

			//for test
			printk("unchange port	= %s, k=%d\n",&r_buf[j+1+1],k);

			p_refuse_port[i] = s2i(&r_buf[j+1+1]);

			i++;

			//k+1：表示“端口字符串长度+等号长度+空格”
			j += (k+1+1);
		}
		else
		{
			j++;
		}
	}	

	//----------------------------------------------------------------------
	//测试打印 refuse port[]
	//----------------------------------------------------------------------
	for(j=0;j<i;j++)
	{
		printk("refuse_port[%d]	= %d\n",j,p_refuse_port[j]);
	}
	
}

//=================================================================
// 通过端口过滤tcp数据包
//=================================================================
int refuse_port(char *type,struct sk_buff *skb)  
{  
    int retval = NF_ACCEPT;  
         
    struct iphdr *iph = ip_hdr(skb);    
    struct tcphdr *tcp = NULL;  
      
    //对于tcp数据包（udp的暂时不算）  
    if( iph->protocol == IPPROTO_TCP )  
    {  
        tcp = tcp_hdr(skb);	
  
        printk("%s: "  
                "%d.%d.%d.%d => %d.%d.%d.%d "  
                "%u -- %u\n",  
                type,  
                (iph->saddr&0x000000FF)>>0,  
                (iph->saddr&0x0000FF00)>>8,  
                (iph->saddr&0x00FF0000)>>16,  
                (iph->saddr&0xFF000000)>>24,  
                (iph->daddr&0x000000FF)>>0,  
                (iph->daddr&0x0000FF00)>>8,  
                (iph->daddr&0x00FF0000)>>16,  
                (iph->daddr&0xFF000000)>>24,  
                htons(tcp->source),  
                htons(tcp->dest)  
                );  
  
	int i;
	while(p_refuse_port[i])
	{
		if (p_refuse_port[i] == htons(tcp->dest))
		{
			retval 	= NF_DROP;
			break;				
		}		
		i++;
	}

	
    }  
  
    return retval;  
} 

//=================================================================
// 通过端口过滤tcp数据包
//=================================================================
int refuse_port_1(char *type,struct sk_buff *skb)  
{  
    int retval = NF_ACCEPT;  
         
    struct iphdr *iph = ip_hdr(skb);    
    struct tcphdr *tcp = NULL;  
      
    //对于tcp数据包（udp的暂时不算）  
    if( iph->protocol == IPPROTO_TCP )  
    {  
        tcp = tcp_hdr(skb);	
  
        printk("%s: "  
                "%d.%d.%d.%d => %d.%d.%d.%d "  
                "%u -- %u\n",  
                type,  
                (iph->saddr&0x000000FF)>>0,  
                (iph->saddr&0x0000FF00)>>8,  
                (iph->saddr&0x00FF0000)>>16,  
                (iph->saddr&0xFF000000)>>24,  
                (iph->daddr&0x000000FF)>>0,  
                (iph->daddr&0x0000FF00)>>8,  
                (iph->daddr&0x00FF0000)>>16,  
                (iph->daddr&0xFF000000)>>24,  
                htons(tcp->source),  
                htons(tcp->dest)  
                );  
  
	
	switch(htons(tcp->dest))
	{
		//丢弃 80 , 1000, 10000 端口数据包
		case 80:
		case 1000:
		case 10000:
			retval 	= NF_DROP;
			break;
		default:
			retval	= NF_ACCEPT;
			break;
	}
    }  
  
    return retval;  
} 

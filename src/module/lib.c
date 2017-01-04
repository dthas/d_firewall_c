//===========================================================================
// lib.c
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
#include	"module_prototype.h"


//=================================================================
// 打印数据包信息
//=================================================================
int print_info(char *type,struct sk_buff *skb)  
{  
    int retval = NF_ACCEPT;  
         
    struct iphdr *iph = ip_hdr(skb);    
    struct tcphdr *tcp = NULL;  
     
    // 打印tcp数据包  
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
      }  
  
    return retval;  
}  

void str_copy(char *dest, char *src)
{
	while(*src != NULL)
	{
		*dest = *src;
		dest++;
		src++;
	}
}

void str_cpy(char *dest, char *src, int len)
{
	int i;

	for(i=0; i<len; i++)
	{
		*dest++ = *src++;
	}	
}


int str_len(char *buf)
{
	int len = 0;

	while(*buf != NULL)
	{
		len++;
		buf++;
	}

	return len;
}


int 	squ(int num, int ind)
{
	int i; 
	int res = 1;
	for(i=0; i<num; i++)
	{
		res = res * ind;
	}

	return res;
}

int	s2i(char * str)
{
	int len	= str_len(str);
	int sum = 0;

	//for test
	//printk("s2i::str=%s, len=%d\n",str, len);

	int i,j,k;
	for(i=len-1, j=0; i>=0; i--,j++)	
	{
		k 	= str[i] - '0';
		k 	= k * squ(j, 10);		

		//for test
		//printk("s2i::k=%d, ",k);

		sum	= sum + k;

		//for test
		//printk("s2i::sum=%d\n",sum);
	}

	return sum;
}



//===========================================================================
// change string(192.168.131.1) to struct iaddr
//===========================================================================
void s2ip(struct iaddr * ip, char *buf)
{
	int i_len 	= str_len(buf);

	//for test
	//printk("1) s2ip :: i_len=%d, r_ip=%s\n",i_len, buf);

	char r_tmp[4];
	int x,y,z;

	unsigned char *q = ip;

	for(x=0,y=0;x<=i_len;x++)
	{
		if(buf[x] == 0x2e)
		{
			r_tmp[y]	= NULL;
			y		= 0;

			*q = s2i(r_tmp);

			//for test
			//printk("2) s2ip::i_len=%d, y=%d, r_tmp=%s, *q=%d\n",i_len, y, r_tmp, *q);
								
			q++;								
		}
		else if(buf[x] == NULL)
		{
			r_tmp[y]	= NULL;

			*q = s2i(r_tmp);

			//for test
			//printk("3) s2ip::i_len=%d, y=%d, r_tmp=%s, *q=%d\n",i_len, y, r_tmp, *q);
		}
		else
		{
			r_tmp[y]	= buf[x];
			y++;
		}
	}						
}




int chk_src_dest_ip(struct iaddr *src_ip, struct iaddr *dest_ip)
{
	if( (src_ip->addr1 == dest_ip->addr1) &&
	    (src_ip->addr2 == dest_ip->addr2) &&
	    (src_ip->addr3 == dest_ip->addr3) &&
	    (src_ip->addr4 == dest_ip->addr4) )
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


void	empty_buf(unsigned int start_addr, int size_in_byte)
{
	int size= size_in_byte;
	char *p	= (char*)start_addr;

	int i;
	for(i=0; i < size; i++)
	{
		p[i] = '\0';
	} 
}









/*
//=================================================================
// 输出信息
//=================================================================
void	outfile(char *filename, char *data, int len)
{
	FILE *fp_w;
	int i;

	fp_w =	fopen(filename,"w");

	for(i=0; i<len; i++)
	{
		fputc(*(data+i), fp_w);		
	}

	fclose(fp_w);
}
*/

//=================================================================
// 输出信息
//=================================================================
char*	infile(char *filename, char *data, int len)
{
	//for test
	printk("infile::filename=%s, len=%d\n", filename, len);

	mm_segment_t old_fs;
	loff_t pos; 
	struct file *fp_r = NULL;
	int j;
		
	fp_r = filp_open(filename, O_RDONLY,0);	
		
	old_fs	= get_fs();
  	set_fs(KERNEL_DS);  
  	pos	= 0;
	vfs_read(fp_r,data,sizeof(data),&pos);
	set_fs(old_fs);

	/*
	//for test
	printk("infile::data:\n");
	for(j=0;j<NR_CHAR_FILE;j++)
	{
		printk("%02x", data[j]);
	}
	*/

	filp_close(fp_r,NULL);

	return data;
}


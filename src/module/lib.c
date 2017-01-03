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
	//for test
	printk("1)s2ip::buf=%s\n",buf);


	char tmpb[4];
	int len 	= str_len(buf);

	//for test
	printk("2)s2ip::len=%d\n",len);

	unsigned char *q = (unsigned char *)ip;

	empty_buf(tmpb, 4);

	//chang . to \0
	int i,j;
	for(j=0, i=0; i<=len, q!=NULL; i++)
	{
		if(buf[i] == NULL)
		{
			break;
		}
		else if(buf[i] == 0x2e)		//判断 .
		{
			//buf[i] = NULL;
			tmpb[j]= NULL;
			*q = s2i(tmpb);

			empty_buf(tmpb, 4);
			j = 0;
			q++;
		}
		else
		{
			tmpb[j] = buf[i];
			j++;
		}

		//for test
		printk("3)s2ip::j=%d, *q=%d\n",j, *q);
	}

	tmpb[j]= NULL;
	*q = s2i(tmpb);

	//for test
	printk("4)s2ip::j=%d, *q=%d\n",j, *q);
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


//=================================================================
// 输出信息
//=================================================================
char*	infile(char *filename, char *data, int len)
{
	FILE *fp_r;
	int i;

	fp_r =	fopen(filename,"r");

	for(i=0; i<len; i++)
	{
		fgetc(*(data+i), fp_r);		
	}

	fclose(fp_r);

	return data;
}
*/

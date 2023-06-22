//#define __KERNEL__
//#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#define MATCH	1
#define NMATCH	0
#define PASS    1
#define NPASS   0

int enable_flag = 1;//作用暂时不明
int white_or_black_flag=1;//0表示黑，1表示简化版本的白

struct nf_hook_ops myhook;
//置为0表示用户在命令行输入的时候这一个选项置为空，默认都通过
//在黑白名单情况下，置为空是否都代表着默许放行，这个仍需考虑
//例如：在ipaddr_check中，如果源和目标的用户输入都为空（0），不用判断直接放行
unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

struct sk_buff *tmpskb;
struct iphdr *piphdr;

int port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
		return MATCH;
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}


//ipaddr_check_black返回MATCH/NMATCH
//例如if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH)是来合起来判断saddr和daddr分别和已经存入的用户输入数据是否配对
//不论什么时候源和目的都是成对存在的
int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr) //在白名单中，if (controlled_saddr == saddr||con)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

//如果用户没有输入，默认禁止，如果用户只输入了源和目标中的其中一个，也禁止
int port_check_white(unsigned short srcport, unsigned short dstport)
{
    if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))      //有效输入的情况，必须将源和目标都输入进来
    {
        if(((controlled_srcport == srcport) && (controlled_dstport == dstport))||((controlled_srcport == dstport) && (controlled_dstport == srcport)))
            return PASS;
        else
            return NPASS;
    }
    else
    {
        printk("The port_check return NPASS due to incomplete order! flag=1 white \n");
        return NPASS;
    }

}

//简化白名单下只过滤ip地址，对于包类型和端口地址均不过滤
int port_check_white_simplified(unsigned short srcport, unsigned short dstport)
{
    return PASS;
}


int ipaddr_check_white(unsigned int saddr, unsigned int daddr)
{
    if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))      //有效输入的情况，必须将源和目标都输入进来
    {
        if(((controlled_saddr == saddr) && (controlled_daddr == daddr))||((controlled_saddr == daddr) && (controlled_daddr == saddr)))
            return PASS;
        else
            return NPASS;
    }
    else
    {
        printk("The ipaddr_check return NPASS due to incomplete order! flag=1 white \n");
        return NPASS;
    }

}

int ipaddr_check_white_simplified(unsigned int saddr, unsigned int daddr)
{
    return ipaddr_check_white(saddr,daddr);
}

int icmp_check(void)
{
	struct icmphdr *picmphdr;
//  	printk("<0>This is an ICMP packet.\n");
   picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

   //黑名单
    if(white_or_black_flag==0)
    {
        if (picmphdr->type == 0)
        {
            if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH)
            {
                printk("An ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        if (picmphdr->type == 8){
            if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH)
            {
                printk("An ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }

    //白名单
    if(white_or_black_flag==1)
    {
        if (picmphdr->type == 0)
        {
            if (ipaddr_check_white_simplified(piphdr->daddr,piphdr->saddr) == NPASS)
            {
                printk("An ICMP packet is denied! flag=1 white \n");
                return NF_DROP;
            }
        }
        if (picmphdr->type == 8){
            if (ipaddr_check_white_simplified(piphdr->saddr,piphdr->daddr) == NPASS)
            {
                printk("An ICMP packet is denied! flag=1 white \n");
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }

}

int tcp_check(void){
	struct tcphdr *ptcphdr;
//   printk("<0>This is an tcp packet.\n");
   ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));


   if(white_or_black_flag==0)
   {
       if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH))
       {
           printk("A TCP packet is denied! \n");
           return NF_DROP;
       }
       else
           return NF_ACCEPT;
   }


   if(white_or_black_flag==1)
   {
       if ((ipaddr_check_white_simplified(piphdr->saddr,piphdr->daddr) == PASS) && (port_check_white_simplified(ptcphdr->source,ptcphdr->dest) == PASS))
       {
           printk("A TCP packet is accepted!  flag=1 white\n");
           return NF_ACCEPT;
       }
       else
       {
           printk("A TCP packet is denied!  flag=1 white\n");
           return NF_DROP;
       }
   }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }
}

int udp_check(void){
	struct udphdr *pudphdr;
//   printk("<0>This is an udp packet.\n");
   pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));


   if(white_or_black_flag==0)
    {
        if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH))
        {
            printk("A UDP packet is denied! \n");
            return NF_DROP;
        }
        else
            return NF_ACCEPT;
    }


    if(white_or_black_flag==1)
    {
        if ((ipaddr_check_white_simplified(piphdr->saddr,piphdr->daddr) == PASS) && (port_check_white_simplified(pudphdr->source,pudphdr->dest) == PASS))
        {
            printk("A UDP packet is accepted!  flag=1 white\n");
            return NF_ACCEPT;
        }
        else
        {
            printk("A UDP packet is denied!  flag=1 white\n");
            return NF_DROP;
        }
    }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }
}

/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){

	/*if (enable_flag == 0)
		return NF_ACCEPT;*/  //作用不明，暂时删除
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

    if(white_or_black_flag==0)
    {
        if(piphdr->protocol != controlled_protocol)
            return NF_ACCEPT;                       //黑名单下的机制比较简单粗暴，只要协议类型不符合，肯定不在黑名单里面，直接放行

        if (piphdr->protocol  == 1)  //ICMP packet
            return icmp_check();
        else if (piphdr->protocol  == 6) //TCP packet
            return tcp_check();
        else if (piphdr->protocol  == 17) //UDP packet
            return udp_check();
        else
        {
            printk("Unkonwn type's packet! \n");
            return NF_ACCEPT;
        }
    }


    if(white_or_black_flag==1)
    {
        //将以下这段代码注释掉的原因是：
        //黑名单防火墙是需要对通信协议进行过滤的，他同时过滤通信协议、ip地址、端口
        //此版本的白名单防火墙只对ip地址进行过滤，所以要注释掉，并且在port_check_white_simplified中直接默认放行

        /*if(piphdr->protocol != controlled_protocol)  //其实可以直接返回NF_DROP了事，但加入了调试信息，可以删改
        {
            if (piphdr->protocol  == 1)  //ICMP packet
            {
                printk("A ICMP packet is denied due to unmatched protocol! flag=1 white\n");
                return NF_DROP;
            }
            else if (piphdr->protocol  == 6) //TCP packet
            {
                printk("A TCP packet is denied due to unmatched protocol! flag=1 white\n");
                return NF_DROP;

            }
            else if (piphdr->protocol  == 17) //UDP packet
            {
                printk("A UDP packet is denied due to unmatched protocol! flag=1 white\n");
                return NF_DROP;
            }
            else
            {
                printk("An unknown packet is denied due to unmatched protocol! flag=1 white\n");
                return NF_DROP;
            }
        }*/

        if (piphdr->protocol  == 1)  //ICMP packet
            return icmp_check();
        else if (piphdr->protocol  == 6) //TCP packet
            return tcp_check();
        else if (piphdr->protocol  == 17) //UDP packet
            return udp_check();
        else
        {
            printk("Unkonwn type's packet! Special information! Please pay attention! flag=1 white\n");
            printk("The related information is in line 343! flag=1 white\n");
            return NF_ACCEPT;
        }
    }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }

}

static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;

	pchar = controlinfo;

	if (len == 0){
		enable_flag = 0;
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);

	/*enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);*/
	return len;
}


struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};


static int __init initmodule(void)
{
	int ret;
   printk("Init Module\n");
   myhook.hook=hook_func;
   myhook.hooknum=NF_INET_LOCAL_OUT;
   myhook.pf=PF_INET;
   myhook.priority=NF_IP_PRI_FIRST;

   nf_register_net_hook(&init_net,&myhook);

   ret = register_chrdev(124, "/dev/controlinfo", &fops); 	// 向系统注册设备结点文件
   if (ret != 0) printk("Can't register device file! \n");

   return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "controlinfo");	 // 向系统注销设备结点文件
        printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");

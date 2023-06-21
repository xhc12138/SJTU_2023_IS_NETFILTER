//#define __KERNEL__
//#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>t
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#define MATCH		1
#define NMATCH	0

int enable_flag = 1;//������ʱ����
int white_or_black_flag=1;//0��ʾ�ڣ�1��ʾ��

struct nf_hook_ops myhook;
//��Ϊ0��ʾ�û��������������ʱ����һ��ѡ����Ϊ�գ�Ĭ�϶�ͨ��
//�ںڰ���������£���Ϊ���Ƿ񶼴�����Ĭ����У�������迼��
//���磺��ipaddr_check�У����Դ��Ŀ����û����붼Ϊ�գ�0���������ж�ֱ�ӷ���
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


//ipaddr_check_black����MATCH/NMATCH
//����if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH)�����������ж�saddr��daddr�ֱ���Ѿ�������û����������Ƿ����
//����ʲôʱ��Դ��Ŀ�Ķ��ǳɶԴ��ڵ�
int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr) //�ڰ������У�if (controlled_saddr == saddr||con)
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

int icmp_check(void)
{
	struct icmphdr *picmphdr;
//  	printk("<0>This is an ICMP packet.\n");
   picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

    //�ڰ������߼��Ĳ�ͬ����ƥ��֮��Ĳ���
    // picmphdr->type==0Ӧ��
    // picmphdr->type==8����
	if (picmphdr->type == 0)
    {
			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH)
            {
			 	if(white_or_black_flag==0)
                {
                    printk("An ICMP packet is denied! \n");
                    return NF_DROP;
                }
                else
                {
                    printk("An ICMP packet is accepted! flag=1 white \n");
                    return NF_ACCEPT;
                }
			}
	}
	if (picmphdr->type == 8)
    {
        if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH)
        {
            if(white_or_black_flag==0)
            {
                printk("An ICMP packet is denied! \n");
                return NF_DROP;
            }
            else
            {
                printk("An ICMP packet is accepted! flag=1 white \n");
                return NF_ACCEPT;
            }
        }
	}
    return -1;
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
   else
   {
       if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH))
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
    else
    {
        if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH))
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
}

/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func_LOCAL_OUT(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){

	/*if (enable_flag == 0)
		return NF_ACCEPT;*/  //���ò�������ʱɾ��
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

    if(white_or_black_flag==0)
    {
        if(piphdr->protocol != controlled_protocol)
            return NF_ACCEPT;                       //�������µĻ��ƱȽϼ򵥴ֱ���ֻҪЭ�����Ͳ����ϣ��϶����ں��������棬ֱ�ӷ���

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
    else
    {
        if(piphdr->protocol != controlled_protocol)
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
        }

        if (piphdr->protocol  == 1)  //ICMP packet
            return icmp_check();
        else if (piphdr->protocol  == 6) //TCP packet
            return tcp_check();
        else if (piphdr->protocol  == 17) //UDP packet
            return udp_check();
        else
        {
            printk("Unkonwn type's packet!  flag=1 white\n");
            return NF_DROP;
        }
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

   ret = register_chrdev(124, "/dev/controlinfo", &fops); 	// ��ϵͳע���豸����ļ�
   if (ret != 0) printk("Can't register device file! \n");

   return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "controlinfo");	 // ��ϵͳע���豸����ļ�
        printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");

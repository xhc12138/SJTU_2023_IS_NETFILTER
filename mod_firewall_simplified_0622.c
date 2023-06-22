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

int enable_flag = 1;//������ʱ����
int white_or_black_flag=1;//0��ʾ�ڣ�1��ʾ�򻯰汾�İ�

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

//����û�û�����룬Ĭ�Ͻ�ֹ������û�ֻ������Դ��Ŀ���е�����һ����Ҳ��ֹ
int port_check_white(unsigned short srcport, unsigned short dstport)
{
    if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))      //��Ч�������������뽫Դ��Ŀ�궼�������
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

//�򻯰�������ֻ����ip��ַ�����ڰ����ͺͶ˿ڵ�ַ��������
int port_check_white_simplified(unsigned short srcport, unsigned short dstport)
{
    return PASS;
}


int ipaddr_check_white(unsigned int saddr, unsigned int daddr)
{
    if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))      //��Ч�������������뽫Դ��Ŀ�궼�������
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

   //������
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

    //������
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


    if(white_or_black_flag==1)
    {
        //��������δ���ע�͵���ԭ���ǣ�
        //����������ǽ����Ҫ��ͨ��Э����й��˵ģ���ͬʱ����ͨ��Э�顢ip��ַ���˿�
        //�˰汾�İ���������ǽֻ��ip��ַ���й��ˣ�����Ҫע�͵���������port_check_white_simplified��ֱ��Ĭ�Ϸ���

        /*if(piphdr->protocol != controlled_protocol)  //��ʵ����ֱ�ӷ���NF_DROP���£��������˵�����Ϣ������ɾ��
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

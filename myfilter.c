#include <linux/skbuff.h>
#include <linux/ip.h>                  /* For IP header */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


unsigned long num = 1;
static struct nf_hook_ops nfho;
static unsigned char my_ip[4] = {192, 168, 0, 100};

unsigned short my_ntohs(unsigned short value) {

    unsigned short result;
    ((unsigned char*)&result)[0] = ((unsigned char*)&value)[1]; 
    ((unsigned char*)&result)[1] = ((unsigned char*)&value)[0];
    return result;	
}
/* ע���hook������ʵ�� */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct iphdr * iph = ip_hdr(sb);
           

    if (sb && iph &&
        memcmp(&iph->saddr, my_ip, 3) != 0 && 
        memcmp(&iph->daddr, my_ip, 4) == 0) {
        //printk("Dropped packet (%d)\n", num++);
        printk("%d.%d.%d.%d -> %d.%d.%d.%d protocol=%d len=%d\n", 
          ((unsigned char*)(&(iph->saddr)))[0],
          ((unsigned char*)(&(iph->saddr)))[1],
          ((unsigned char*)(&(iph->saddr)))[2],
          ((unsigned char*)(&(iph->saddr)))[3],
          ((unsigned char*)(&(iph->daddr)))[0],
          ((unsigned char*)(&(iph->daddr)))[1],
          ((unsigned char*)(&(iph->daddr)))[2],
          ((unsigned char*)(&(iph->daddr)))[3], 
          (iph->protocol), 
          my_ntohs((iph->tot_len)));
        /*
        int len =   my_ntohs((iph->tot_len));
        
        int i;
        for (i=20;i<len; i++) {
        printk("%c", ((char *)iph)[i]);
        }
        printk("\n");
          */     

        return NF_DROP;
    } else {
        return NF_ACCEPT;
    }
}

/* ��ʼ������ */
static int myfilter_init(void)
{
    printk( "%s() \n", __func__);
    /* ������ǵ�hook���ݽṹ */
    nfho.hook     = hook_func;         /* ������ */
    nfho.owner= THIS_MODULE;
    nfho.hooknum  = NF_INET_PRE_ROUTING; /* ʹ��IPv4�ĵ�һ��hook */
    //nfho.hooknum  = NF_INET_PRE_ROUTING; /* ʹ��IPv4�ĵ�һ��hook */
//    nfho.hooknum  = NF_INET_LOCAL_IN; /* ʹ��IPv4�ĵ�һ��hook */
//    nfho.pf       = PF_INET;
    nfho.pf       = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_FIRST;   /* �����ǵĺ�������ִ�� */

    nf_register_hook(&nfho);

    return 0;
}

/* ������� */
static void myfilter_exit(void)
{
    printk("%s() : bye bye\n", __func__);
    nf_unregister_hook(&nfho);
}


module_init(myfilter_init);
module_exit(myfilter_exit);

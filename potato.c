// #define __KERNEL__
// #define MODULE
// #include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
// #include <linux/init.h>
// #include <linux/netdevice.h>
// #include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>


MODULE_AUTHOR("iamgroot42");
MODULE_AUTHOR("GPL");
MODULE_DESCRIPTION("A netfilter kernel module. Made as a course assignment for Network Security (CSE550)");

static struct nf_hook_ops netfilter_ops;

int flag_count(struct tcphdr *tcph){
	int count = 0;
	if(tcph->fin) ++count;
	if(tcph->syn) ++count;
	if(tcph->rst) ++count;
	if(tcph->psh) ++count;
	if(tcph->ack) ++count;
	if(tcph->urg) ++count;
	if(tcph->ece) ++count;
	if(tcph->cwr) ++count;
	return count;
}

void xmas_attack_drop(struct tcphdr *tcph){
	if(tcph->fin && tcph->psh && tcph->urg){
		printk(KERN_INFO "(iamgroot42) XMAS scan detected!\n");
	}
}

void null_scan_drop(struct tcphdr *tcph){
	if(flag_count(tcph) == 0){
		printk(KERN_INFO "(iamgroot42) NULL scan detected!\n");
	}
}

void fin_scan_drop(struct tcphdr *tcph){
	if(tcph->fin == 1 && flag_count(tcph) == 1){
		printk(KERN_INFO "(iamgroot42) FIN scan detected!\n");
	}
}

void ack_scan_drop(struct tcphdr *tcph){
	if(tcph->ack == 1 && flag_count(tcph) == 1 && tcph->seq == 0){
		printk(KERN_INFO "(iamgroot42) ACK scan detected!\n");
	}
}

unsigned int main_hook(void *priv, struct sk_buff *skb,const struct nf_hook_state *state){
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);
	if (skb){
		// Only look at TCP packets
		if (iph->protocol == IPPROTO_TCP){
			tcph = tcp_hdr(skb);
			if(tcph){
				null_scan_drop(tcph);
				xmas_attack_drop(tcph);
				fin_scan_drop(tcph);
				ack_scan_drop(tcph);
			}
		}
	}
	return NF_ACCEPT;
}

static int __init hello_init(void){
	printk(KERN_INFO "(iamgroot42) Loading module!\n");
	netfilter_ops.hook = main_hook;
	netfilter_ops.pf = PF_INET;        
	netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops);
    return 0;
}

static void __exit hello_cleanup(void){
    printk(KERN_INFO "(iamgroot42) Cleaning up module!\n");
    nf_unregister_hook(&netfilter_ops);
}

module_init(hello_init);
module_exit(hello_cleanup);

// sudo insmod potato.ko
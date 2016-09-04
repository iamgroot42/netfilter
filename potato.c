#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

MODULE_AUTHOR("Anshuman");
MODULE_DESCRIPTION("A netfilter kernel module. Made as a course assignment for Network Security (CSE550)");

static struct nf_hook_ops netfilter_ops;

unsigned int log_hook(){
	printk(KERN_INFO "Cleaning up module.\n");
	return NF_ACCEPT;
}

int xmas_attack_drop(){
	// xmas packet checking logic
	return 1;
}

int syn_flood_drop(){
	// synn attack checking logic
	return 1;
}

int null_scan_drop(){
	// null packet checking logic
	return 1;
}

unsigned int main_hook(
	unsigned int hooknum,
	struct sk_buff **skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff*)){
		if(xmas_attack_drop()){
			return NF_DROP;
		}else if(syn_flood_drop()){
			return NF_DROP;
		}else if(null_scan_drop()){
			return NF_DROP;
		}else if(){
			return NF_DROP;
		}
		return log_hook();
}

static int __init hello_init(void){
	printk(KERN_INFO "Loading module!\n");
	netfilter_ops.hook = main_hook;
	netfilter_ops.pf = PF_INET;        
	netfilter_ops.hooknum = NF_IP_PRE_ROUTING;
	netfilter_ops.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops);
    return 0;
}

static void __exit hello_cleanup(void){
    printk(KERN_INFO "Cleaning up module!\n");
    nf_unregister_hook(&netfilter_ops);
}

module_init(hello_init);
module_exit(hello_cleanup);

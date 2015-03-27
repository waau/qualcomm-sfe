/*
 * sfe_backport.h
 *	Shortcut forwarding engine compatible header file.
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define sfe_cm_ipv4_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int __sfe_cm_ipv4_post_routing_hook(const struct nf_hook_ops *OPS, \
						    struct sk_buff *SKB, \
						    const struct net_device *UNUSED, \
						    const struct net_device *OUT, \
						    int (*OKFN)(struct sk_buff *))

#define sfe_cm_ipv6_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int __sfe_cm_ipv6_post_routing_hook(const struct nf_hook_ops *OPS, \
						    struct sk_buff *SKB, \
						    const struct net_device *UNUSED, \
						    const struct net_device *OUT, \
						    int (*OKFN)(struct sk_buff *))
#else
#define sfe_cm_ipv4_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int __sfe_cm_ipv4_post_routing_hook(unsigned int HOOKNUM, \
						    struct sk_buff *SKB, \
						    const struct net_device *UNUSED, \
						    const struct net_device *OUT, \
						    int (*OKFN)(struct sk_buff *))

#define sfe_cm_ipv6_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int __sfe_cm_ipv6_post_routing_hook(unsigned int HOOKNUM, \
						    struct sk_buff *SKB, \
						    const struct net_device *UNUSED, \
						    const struct net_device *OUT, \
						    int (*OKFN)(struct sk_buff *))
#endif

/*
 * sfe_dev_get_master
 * 	get master of bridge port, and hold it
 */
static inline struct net_device *sfe_dev_get_master(struct net_device *dev)
{
	struct net_device *master;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(dev);
	if (master)
		dev_hold(master);

	rcu_read_unlock();
#else
	master = dev->master;
	if (master)
		dev_hold(master);
#endif
	return master;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define SFE_NF_CONN_ACCT(NM) struct nf_conn_acct *NM
#else
#define SFE_NF_CONN_ACCT(NM) struct nf_conn_counter *NM
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define SFE_ACCT_COUNTER(NM) ((NM)->counter)
#else
#define SFE_ACCT_COUNTER(NM) (NM)
#endif

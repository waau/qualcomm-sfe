#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#define sfe_cm_ipv4_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int __sfe_cm_ipv4_post_routing_hook(const struct nf_hook_ops *OPS, \
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
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#define SFE_DEV_MASTER(DEV) netdev_master_upper_dev_get(DEV);
#else
#define SFE_DEV_MASTER(DEV) (DEV)->master;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#define SFE_NF_CONN_ACCT(NM) struct nf_conn_acct *NM
#else
#define SFE_NF_CONN_ACCT(NM) struct nf_conn_counter *NM
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#define SFE_ACCT_COUNTER(NM) (NM)->counter
#else
#define SFE_ACCT_COUNTER(NM) (NM)
#endif

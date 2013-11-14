/*
 *  Copyright (C) 2013 Matthew McClintock <mmcclint@codeaurora.org>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>

enum {
	FAST_CLASSIFIER_A_UNSPEC,
	FAST_CLASSIFIER_A_MSG,
	__FAST_CLASSIFIER_A_MAX,
};
#define FAST_CLASSIFIER_A_MAX (__FAST_CLASSIFIER_A_MAX - 1)

static struct nla_policy fast_classifier_genl_policy[FAST_CLASSIFIER_A_MAX + 1] = {
	[FAST_CLASSIFIER_A_MSG] = { .type = NLA_NUL_STRING },
};

static struct genl_family fast_classifier_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "FAST_CLASSIFIER",
	.version = 1,
	.maxattr = FAST_CLASSIFIER_A_MAX,
};

enum {
	FAST_CLASSIFIER_C_UNSPEC,
	FAST_CLASSIFIER_C_RECV,
	__FAST_CLASSIFIER_C_MAX,
};
#define FAST_CLASSIFIER_C_MAX (__FAST_CLASSIFIER_C_MAX - 1)

static int fast_classifier_recv(struct sk_buff *skb, struct genl_info *info);

static struct genl_ops fast_classifier_gnl_ops_recv = {
	.cmd = FAST_CLASSIFIER_C_RECV,
	.flags = 0,
	.policy = fast_classifier_genl_policy,
	.doit = fast_classifier_recv,
	.dumpit = NULL,
};

static int fast_classifier_recv(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	char *data;

	na = info->attrs[FAST_CLASSIFIER_C_RECV];
	data = nla_data(na);
	printk(KERN_CRIT "fast-classifier: message = %s\n", data);
	return 0;
}

int init_module(void)
{
	int rc;
	struct sk_buff *skb;
	struct nl_msg *msg;

	printk(KERN_ALERT "fast-classifier: starting up\n");

	rc = genl_register_family(&fast_classifier_gnl_family);
	if (rc != 0)
	     goto failure;

	rc = genl_register_ops(&fast_classifier_gnl_family, &fast_classifier_gnl_ops_recv);
	if (rc != 0)
		goto failure1;

	printk(KERN_ALERT "fast-classifier: registered\n");

	return 0;

failure1:
	genl_unregister_family(&fast_classifier_gnl_family);
failure:
	return -1;
}

void cleanup_module(void)
{
	int rc;

	printk(KERN_ALERT "fast-classifier: shutting down\n");

	rc = genl_register_family(&fast_classifier_gnl_family);
	if (rc != 0)
		printk(KERN_CRIT "Unable to unreigster genl_family\n");
		return -1;

	rc = genl_register_ops(&fast_classifier_gnl_family, &fast_classifier_gnl_ops_recv);
	if (rc != 0)
		printk(KERN_CRIT "Unable to unreigster genl_ops\n");
		return -1;

	return 0;
}

MODULE_LICENSE("GPL");


/*
 * User space header to send message to the fast classifier
 *
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/if_ether.h>

#define FAST_CLASSIFIER_GENL_VERSION	(1)
#define FAST_CLASSIFIER_GENL_NAME	"FC"
#define FAST_CLASSIFIER_GENL_MCGRP	"FC_MCGRP"
#define FAST_CLASSIFIER_GENL_HDRSIZE	(0)

enum {
	FAST_CLASSIFIER_A_UNSPEC,
	FAST_CLASSIFIER_A_TUPLE,
	__FAST_CLASSIFIER_A_MAX,
};
#define FAST_CLASSIFIER_A_MAX (__FAST_CLASSIFIER_A_MAX - 1)

enum {
	FAST_CLASSIFIER_C_UNSPEC,
	FAST_CLASSIFIER_C_OFFLOAD,
	FAST_CLASSIFIER_C_OFFLOADED,
	FAST_CLASSIFIER_C_DONE,
	__FAST_CLASSIFIER_C_MAX,
};
#define FAST_CLASSIFIER_C_MAX (__FAST_CLASSIFIER_C_MAX - 1)

struct fast_classifier_tuple {
	unsigned char proto;
	unsigned long src_saddr;
	unsigned long dst_saddr;
	unsigned short sport;
	unsigned short dport;
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
};

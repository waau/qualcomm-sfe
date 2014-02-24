/*
 * sfe_ipv4.h
 *	Shortcut forwarding engine.
 *
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * IPv4 connection flags.
 */
#define SFE_IPV4_CREATE_FLAG_NO_SEQ_CHECK 0x1
 					/* Indicates that we should not check sequence numbers */

/*
 * IPv4 connection creation structure.
 */
struct sfe_ipv4_create {
	int protocol;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	uint32_t flags;
	uint32_t src_mtu;
	uint32_t dest_mtu;
	__be32 src_ip;
	__be32 src_ip_xlate;
	__be32 dest_ip;
	__be32 dest_ip_xlate;
	__be16 src_port;
	__be16 src_port_xlate;
	__be16 dest_port;
	__be16 dest_port_xlate;
	uint8_t src_mac[ETH_ALEN];
	uint8_t src_mac_xlate[ETH_ALEN];
	uint8_t dest_mac[ETH_ALEN];
	uint8_t dest_mac_xlate[ETH_ALEN];
	uint8_t src_td_window_scale;
	uint32_t src_td_max_window;
	uint32_t src_td_end;
	uint32_t src_td_max_end;
	uint8_t dest_td_window_scale;
	uint32_t dest_td_max_window;
	uint32_t dest_td_end;
	uint32_t dest_td_max_end;
	uint32_t mark;
};

/*
 * IPv4 connection destruction structure.
 */
struct sfe_ipv4_destroy {
	int protocol;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
};

/*
 * Structure used to sync IPv4 connection stats/state back within the system.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct sfe_ipv4_sync {
	struct net_device *src_dev;
	struct net_device *dest_dev;
	int protocol;			/* IP protocol number (IPPROTO_...) */
	__be32 src_ip;			/* Non-NAT source address, i.e. the creator of the connection */
	__be16 src_port;		/* Non-NAT source port */
	__be32 dest_ip;			/* Non-NAT destination address, i.e. to whom the connection was created */
	__be16 dest_port;		/* Non-NAT destination port */
	uint32_t src_td_max_window;
	uint32_t src_td_end;
	uint32_t src_td_max_end;
	uint64_t src_packet_count;
	uint64_t src_byte_count;
	uint32_t src_new_packet_count;
	uint32_t src_new_byte_count;
	uint32_t dest_td_max_window;
	uint32_t dest_td_end;
	uint32_t dest_td_max_end;
	uint64_t dest_packet_count;
	uint64_t dest_byte_count;
	uint32_t dest_new_packet_count;
	uint32_t dest_new_byte_count;
	uint64_t delta_jiffies;		/* Time to be added to the current timeout to keep the connection alive */
};

/*
 * Type used for a sync rule callback.
 */
typedef void (*sfe_ipv4_sync_rule_callback_t)(struct sfe_ipv4_sync *);

extern int sfe_ipv4_recv(struct net_device *dev, struct sk_buff *skb);
extern int sfe_ipv4_create_rule(struct sfe_ipv4_create *sic);
extern void sfe_ipv4_destroy_rule(struct sfe_ipv4_destroy *sid);
extern void sfe_ipv4_destroy_all_rules_for_dev(struct net_device *dev);
extern void sfe_ipv4_register_sync_rule_callback(sfe_ipv4_sync_rule_callback_t callback);
extern void sfe_ipv4_update_rule(struct sfe_ipv4_create *sic);

/*
 * IPv4 connection mark structure
 */
struct sfe_ipv4_mark {
	int protocol;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
	uint32_t mark;
};
extern void sfe_ipv4_mark_rule(struct sfe_ipv4_mark *mark);

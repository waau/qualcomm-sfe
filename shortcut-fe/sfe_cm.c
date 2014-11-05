/*
 * sfe-cm.c
 *	Shortcut forwarding engine connection manager.
 *
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/if_bridge.h>

#include "sfe.h"
#include "sfe_ipv4.h"
#include "sfe_backport.h"

/*
 * Per-module structure.
 */
struct sfe_cm {
	spinlock_t lock;		/* Lock for SMP correctness */

	/*
	 * Control state.
	 */
	struct kobject *sys_sfe_cm;	/* sysfs linkage */

	/*
	 * Callback notifiers.
	 */
	struct notifier_block dev_notifier;
					/* Device notifier */
	struct notifier_block inet_notifier;
					/* IP notifier */
};

struct sfe_cm __sc;

/*
 * Expose the hook for the receive processing.
 */
extern int (*athrs_fast_nat_recv)(struct sk_buff *skb);

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;

/*
 * sfe_cm_recv()
 *	Handle packet receives.
 *
 * Returns 1 if the packet is forwarded or 0 if it isn't.
 */
int sfe_cm_recv(struct sk_buff *skb)
{
	struct net_device *dev;
#if (SFE_HOOK_ABOVE_BRIDGE)
	struct in_device *in_dev;
#endif

	/*
	 * We know that for the vast majority of packets we need the transport
	 * layer header so we may as well start to fetch it now!
	 */
	prefetch(skb->data + 32);
	barrier();

	dev = skb->dev;

#if (SFE_HOOK_ABOVE_BRIDGE)
	/*
	 * Does our input device support IP processing?
	 */
	in_dev = (struct in_device *)dev->ip_ptr;
	if (unlikely(!in_dev)) {
		DEBUG_TRACE("no IP processing for device: %s\n", dev->name);
		return 0;
	}

	/*
	 * Does it have an IP address?  If it doesn't then we can't do anything
	 * interesting here!
	 */
	if (unlikely(!in_dev->ifa_list)) {
		DEBUG_TRACE("no IP address for device: %s\n", dev->name);
		return 0;
	}
#endif

	/*
	 * We're only interested in IP packets.
	 */	
	if (likely(htons(ETH_P_IP) == skb->protocol)) {
		return sfe_ipv4_recv(dev, skb);
	}

	DEBUG_TRACE("not IP packet\n");
	return 0;
}

/*
 * sfe_cm_find_dev_and_mac_addr()
 *	Find the device and MAC address for a given IPv4 address.
 *
 * Returns true if we find the device and MAC address, otherwise false.
 *
 * We look up the rtable entry for the address and, from its neighbour
 * structure, obtain the hardware address.  This means this function also
 * works if the neighbours are routers too.
 */
static bool sfe_cm_find_dev_and_mac_addr(uint32_t addr, struct net_device **dev, uint8_t *mac_addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;
	struct net_device *mac_dev;

	/*
	 * Look up the rtable entry for the IP address then get the hardware
	 * address from its neighbour structure.  This means this work when the
	 * neighbours are routers too.
	 */
	rt = ip_route_output(&init_net, addr, 0, 0, 0);
	if (unlikely(IS_ERR(rt))) {
		return false;
	}

	dst = (struct dst_entry *)rt;

	rcu_read_lock();
	neigh = dst_neigh_lookup(dst, &addr);
	if (unlikely(!neigh)) {
		rcu_read_unlock();
		dst_release(dst);
		return false; 
	}

	if (unlikely(!(neigh->nud_state & NUD_VALID))) {
		neigh_release(neigh);
		rcu_read_unlock();
		dst_release(dst);
		return false;
	}

	mac_dev = neigh->dev;
	if (!mac_dev) {
		neigh_release(neigh);
		rcu_read_unlock();
		dst_release(dst);
		return false;
	}

	memcpy(mac_addr, neigh->ha, (size_t)mac_dev->addr_len);

	dev_hold(mac_dev);
	*dev = mac_dev;
	neigh_release(neigh);
	rcu_read_unlock();
	dst_release(dst);

	return true;
}

/*
 * sfe_cm_ipv4_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
sfe_cm_ipv4_post_routing_hook(hooknum, ops, skb, in_unused, out, okfn)
{
	struct sfe_ipv4_create sic;
	struct net_device *in;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct net_device *dev;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	struct net_device *src_br_dev = NULL;
	struct net_device *dest_br_dev = NULL;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;

	/*
	 * Don't process broadcast or multicast packets.
	 */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST)) {
		DEBUG_TRACE("broadcast, ignoring\n");
		return NF_ACCEPT;
	}
	if (unlikely(skb->pkt_type == PACKET_MULTICAST)) {
		DEBUG_TRACE("multicast, ignoring\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets that are not being forwarded.
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (!in) {
		DEBUG_TRACE("packet not forwarding\n");
		return NF_ACCEPT;
	}

	dev_put(in);

	/*
	 * Don't process packets that aren't being tracked by conntrack.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("no conntrack connection, ignoring\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process untracked connections.
	 */
	if (unlikely(ct == &nf_conntrack_untracked)) {
		DEBUG_TRACE("untracked connection\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process connections that require support from a 'helper' (typically a NAT ALG).
	 */
	if (unlikely(nfct_help(ct))) {
		DEBUG_TRACE("connection has helper\n");
		return NF_ACCEPT;
	}

	/*
	 * Look up the details of our connection in conntrack.
	 *
	 * Note that the data we get from conntrack is for the "ORIGINAL" direction
	 * but our packet may actually be in the "REPLY" direction.
	 */
	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	sic.protocol = (int32_t)orig_tuple.dst.protonum;

	/*
	 * Get addressing information, non-NAT first
	 */
	sic.src_ip = (__be32)orig_tuple.src.u3.ip;
	sic.dest_ip = (__be32)orig_tuple.dst.u3.ip;

	if (ipv4_is_multicast(sic.src_ip) || ipv4_is_multicast(sic.dest_ip)) {
		DEBUG_TRACE("multicast address\n");
		return NF_ACCEPT;
	}

	/*
	 * NAT'ed addresses - note these are as seen from the 'reply' direction
	 * When NAT does not apply to this connection these will be identical to the above.
	 */
	sic.src_ip_xlate = (__be32)reply_tuple.dst.u3.ip;
	sic.dest_ip_xlate = (__be32)reply_tuple.src.u3.ip;

	sic.flags = 0;

	switch (sic.protocol) {
	case IPPROTO_TCP:
		sic.src_port = orig_tuple.src.u.tcp.port;
		sic.dest_port = orig_tuple.dst.u.tcp.port;
		sic.src_port_xlate = reply_tuple.dst.u.tcp.port;
		sic.dest_port_xlate = reply_tuple.src.u.tcp.port;
		sic.src_td_window_scale = ct->proto.tcp.seen[0].td_scale;
		sic.src_td_max_window = ct->proto.tcp.seen[0].td_maxwin;
		sic.src_td_end = ct->proto.tcp.seen[0].td_end;
		sic.src_td_max_end = ct->proto.tcp.seen[0].td_maxend;
		sic.dest_td_window_scale = ct->proto.tcp.seen[1].td_scale;
		sic.dest_td_max_window = ct->proto.tcp.seen[1].td_maxwin;
		sic.dest_td_end = ct->proto.tcp.seen[1].td_end;
		sic.dest_td_max_end = ct->proto.tcp.seen[1].td_maxend;
		if (nf_ct_tcp_no_window_check
		    || (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
		    || (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
			sic.flags |= SFE_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
		}

		/*
		 * Don't try to manage a non-established connection.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
			DEBUG_TRACE("non-established connection\n");
			return NF_ACCEPT;
		}

		/*
		 * If the connection is shutting down do not manage it.
		 * state can not be SYN_SENT, SYN_RECV because connection is assured
		 * Not managed states: FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE.
		 */
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
			spin_unlock_bh(&ct->lock);
			DEBUG_TRACE("connection in termination state: %#x, s: %pI4:%u, d: %pI4:%u\n",
				    ct->proto.tcp.state, &sic.src_ip, ntohs(sic.src_port),
				    &sic.dest_ip, ntohs(sic.dest_port));
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ct->lock);
		break;

	case IPPROTO_UDP:
		sic.src_port = orig_tuple.src.u.udp.port;
		sic.dest_port = orig_tuple.dst.u.udp.port;
		sic.src_port_xlate = reply_tuple.dst.u.udp.port;
		sic.dest_port_xlate = reply_tuple.src.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol %d\n", sic.protocol);
		return NF_ACCEPT;
	}

	/*
	 * Get the net device and MAC addresses that correspond to the various source and
	 * destination host addresses.
	 */
	if (!sfe_cm_find_dev_and_mac_addr(sic.src_ip, &src_dev, sic.src_mac)) {
		DEBUG_TRACE("failed to find MAC address for src IP: %pI4\n", &sic.src_ip);
		return NF_ACCEPT;
	}

	if (!sfe_cm_find_dev_and_mac_addr(sic.src_ip_xlate, &dev, sic.src_mac_xlate)) {
		DEBUG_TRACE("failed to find MAC address for xlate src IP: %pI4\n", &sic.src_ip_xlate);
		goto done1;
	}

	dev_put(dev);

	if (!sfe_cm_find_dev_and_mac_addr(sic.dest_ip, &dev, sic.dest_mac)) {
		DEBUG_TRACE("failed to find MAC address for dest IP: %pI4\n", &sic.dest_ip);
		goto done1;
	}

	dev_put(dev);

	if (!sfe_cm_find_dev_and_mac_addr(sic.dest_ip_xlate, &dest_dev, sic.dest_mac_xlate)) {
		DEBUG_TRACE("failed to find MAC address for xlate dest IP: %pI4\n", &sic.dest_ip_xlate);
		goto done1;
	}

#if (!SFE_HOOK_ABOVE_BRIDGE)
	/*
	 * Now our devices may actually be a bridge interface.  If that's
	 * the case then we need to hunt down the underlying interface.
	 */
	if (src_dev->priv_flags & IFF_EBRIDGE) {
		src_br_dev = br_port_dev_get(src_dev, sic.src_mac);
		if (!src_br_dev) {
			DEBUG_TRACE("no port found on bridge\n");
			goto done2;
		}

		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_EBRIDGE) {
		dest_br_dev = br_port_dev_get(dest_dev, sic.dest_mac_xlate);
		if (!dest_br_dev) {
			DEBUG_TRACE("no port found on bridge\n");
			goto done3;
		}

		dest_dev = dest_br_dev;
	}
#else
	/*
	 * Our devices may actually be part of a bridge interface.  If that's
	 * the case then find the bridge interface instead.
	 */
	if (src_dev->priv_flags & IFF_BRIDGE_PORT) {
		src_br_dev = SFE_DEV_MASTER(src_dev);
		if (!src_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", src_dev->name);
			goto done2;
		}

		dev_hold(src_br_dev);
		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_BRIDGE_PORT) {
		dest_br_dev = SFE_DEV_MASTER(dest_dev);
		if (!dest_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", dest_dev->name);
			goto done3;
		}

		dev_hold(dest_br_dev);
		dest_dev = dest_br_dev;
	}
#endif

	sic.src_dev = src_dev;
	sic.dest_dev = dest_dev;

	sic.src_mtu = src_dev->mtu;
	sic.dest_mtu = dest_dev->mtu;

	sfe_ipv4_create_rule(&sic);

	/*
	 * If we had bridge ports then release them too.
	 */
	if (dest_br_dev) {
		dev_put(dest_br_dev);
	}

done3:
	if (src_br_dev) {
		dev_put(src_br_dev);
	}

done2:
	dev_put(dest_dev);

done1:
	dev_put(src_dev);

	return NF_ACCEPT;
}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * sfe_cm_conntrack_event()
 *	Callback event invoked when a conntrack connection's state changes.
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int sfe_cm_conntrack_event(struct notifier_block *this,
			unsigned long events, void *ptr)
#else
static int sfe_cm_conntrack_event(unsigned int events, struct nf_ct_event *item)
#endif
{
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
	struct nf_ct_event *item = ptr;
#endif
	struct sfe_ipv4_destroy sid;
	struct nf_conn *ct = item->ct;
	struct nf_conntrack_tuple orig_tuple;

	/*
	 * If we don't have a conntrack entry then we're done.
	 */
	if (unlikely(!ct)) {
		DEBUG_WARN("no ct in conntrack event callback\n");
		return NOTIFY_DONE;
	}

	/*
	 * If this is an untracked connection then we can't have any state either.
	 */
	if (unlikely(ct == &nf_conntrack_untracked)) {
		DEBUG_TRACE("ignoring untracked conn\n");
		return NOTIFY_DONE;
	}

	/*
	 * Ignore anything other than IPv4 connections.
	 */
	if (unlikely(nf_ct_l3num(ct) != AF_INET)) {
		DEBUG_TRACE("ignoring non-IPv4 conn\n");
		return NOTIFY_DONE;
	}

	/*
	 * We're only interested in destroy events.
	 */
	if (unlikely(!(events & (1 << IPCT_DESTROY)))) {
		DEBUG_TRACE("ignoring non-destroy event\n");
		return NOTIFY_DONE;
	}

	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	sid.protocol = (int32_t)orig_tuple.dst.protonum;

	/*
	 * Extract information from the conntrack connection.  We're only interested
	 * in nominal connection information (i.e. we're ignoring any NAT information).
	 */
	sid.src_ip = (__be32)orig_tuple.src.u3.ip;
	sid.dest_ip = (__be32)orig_tuple.dst.u3.ip;

	switch (sid.protocol) {
	case IPPROTO_TCP:
		sid.src_port = orig_tuple.src.u.tcp.port;
		sid.dest_port = orig_tuple.dst.u.tcp.port;
		break;

	case IPPROTO_UDP:
		sid.src_port = orig_tuple.src.u.udp.port;
		sid.dest_port = orig_tuple.dst.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol: %d\n", sid.protocol);
		return NOTIFY_DONE;
	}


	sfe_ipv4_destroy_rule(&sid);
	return NOTIFY_DONE;
}

/*
 * Netfilter conntrack event system to monitor connection tracking changes
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static struct notifier_block sfe_cm_conntrack_notifier = {
	.notifier_call = sfe_cm_conntrack_event,
};
#else
static struct nf_ct_event_notifier sfe_cm_conntrack_notifier = {
	.fcn = sfe_cm_conntrack_event,
};
#endif
#endif

/*
 * Structure to establish a hook into the post routing netfilter point - this
 * will pick up local outbound and packets going from one interface to another.
 *
 * Note: see include/linux/netfilter_ipv4.h for info related to priority levels.
 * We want to examine packets after NAT translation and any ALG processing.
 */
static struct nf_hook_ops sfe_cm_ipv4_ops_post_routing[] __read_mostly = {
	{
		.hook = __sfe_cm_ipv4_post_routing_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 1,
	},
};

/*
 * sfe_cm_sync_rule()
 *	Synchronize a connection's state.
 */
static void sfe_cm_sync_rule(struct sfe_ipv4_sync *sis)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	SFE_NF_CONN_ACCT(acct);

	/*
	 * Create a tuple so as to be able to look up a connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = sis->src_ip;
	tuple.src.u.all = (__be16)sis->src_port;
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = sis->dest_ip;
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)sis->protocol;
	tuple.dst.u.all = (__be16)sis->dest_port;

	DEBUG_TRACE("update connection - p: %d, s: %pI4:%u, d: %pI4:%u\n",
		    (int)tuple.dst.protonum,
		    &tuple.src.u3.ip, (unsigned int)ntohs(tuple.src.u.all),
		    &tuple.dst.u3.ip, (unsigned int)ntohs(tuple.dst.u.all));

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h)) {
		DEBUG_TRACE("no connection found\n");
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);

	/*
	 * Only update if this is not a fixed timeout
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		ct->timeout.expires += sis->delta_jiffies;
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].packets, sis->src_packet_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].bytes, sis->src_byte_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].packets, sis->dest_packet_count);
		atomic64_set(&SFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].bytes, sis->dest_byte_count);
		spin_unlock_bh(&ct->lock);
	}

	switch (sis->protocol) {
	case IPPROTO_TCP:
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.seen[0].td_maxwin < sis->src_td_max_window) {
			ct->proto.tcp.seen[0].td_maxwin = sis->src_td_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_end - sis->src_td_end) < 0) {
			ct->proto.tcp.seen[0].td_end = sis->src_td_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_maxend - sis->src_td_max_end) < 0) {
			ct->proto.tcp.seen[0].td_maxend = sis->src_td_max_end;
		}
		if (ct->proto.tcp.seen[1].td_maxwin < sis->dest_td_max_window) {
			ct->proto.tcp.seen[1].td_maxwin = sis->dest_td_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_end - sis->dest_td_end) < 0) {
			ct->proto.tcp.seen[1].td_end = sis->dest_td_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_maxend - sis->dest_td_max_end) < 0) {
			ct->proto.tcp.seen[1].td_maxend = sis->dest_td_max_end;
		}
		spin_unlock_bh(&ct->lock);
		break;
	}

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * sfe_cm_device_event()
 */
static int sfe_cm_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

	switch (event) {
	case NETDEV_DOWN:
		if (dev) {
			sfe_ipv4_destroy_all_rules_for_dev(dev);
		}
		break;
	}

	return NOTIFY_DONE;
}

/*
 * sfe_cm_inet_event()
 */
static int sfe_cm_inet_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
	return sfe_cm_device_event(this, event, dev);
}

/*
 * sfe_cm_init()
 */
static int __init sfe_cm_init(void)
{
	struct sfe_cm *sc = &__sc;
	int result = -1;

	DEBUG_INFO("SFE CM init\n");

	/*
	 * Create sys/sfe_cm
	 */
	sc->sys_sfe_cm = kobject_create_and_add("sfe_cm", NULL);
	if (!sc->sys_sfe_cm) {
		DEBUG_ERROR("failed to register sfe_cm\n");
		goto exit1;
	}

	sc->dev_notifier.notifier_call = sfe_cm_device_event;
	sc->dev_notifier.priority = 1;
	register_netdevice_notifier(&sc->dev_notifier);

	sc->inet_notifier.notifier_call = sfe_cm_inet_event;
	sc->inet_notifier.priority = 1;
	register_inetaddr_notifier(&sc->inet_notifier);

	/*
	 * Register our netfilter hooks.
	 */
	result = nf_register_hooks(sfe_cm_ipv4_ops_post_routing, ARRAY_SIZE(sfe_cm_ipv4_ops_post_routing));
	if (result < 0) {
		DEBUG_ERROR("can't register nf post routing hook: %d\n", result);
		goto exit6;
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/*
	 * Register a notifier hook to get fast notifications of expired connections.
	 */
	result = nf_conntrack_register_notifier(&init_net, &sfe_cm_conntrack_notifier);
	if (result < 0) {
		DEBUG_ERROR("can't register nf notifier hook: %d\n", result);
		goto exit7;
	}
#endif

	spin_lock_init(&sc->lock);

	/*
	 * Hook the receive path in the network stack.
	 */
	BUG_ON(athrs_fast_nat_recv != NULL);
	RCU_INIT_POINTER(athrs_fast_nat_recv, sfe_cm_recv);

	/*
	 * Hook the shortcut sync callback.
	 */
	sfe_ipv4_register_sync_rule_callback(sfe_cm_sync_rule);
	return 0;

#ifdef CONFIG_NF_CONNTRACK_EVENTS
exit7:
#endif
	nf_unregister_hooks(sfe_cm_ipv4_ops_post_routing, ARRAY_SIZE(sfe_cm_ipv4_ops_post_routing));

exit6:
	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);
	kobject_put(sc->sys_sfe_cm);

exit1:
	return result;
}

/*
 * sfe_cm_exit()
 */
static void __exit sfe_cm_exit(void)
{
	struct sfe_cm *sc = &__sc;

	DEBUG_INFO("SFE CM exit\n");

	/*
	 * Unregister our sync callback.
	 */
	sfe_ipv4_register_sync_rule_callback(NULL);

	/*
	 * Unregister our receive callback.
	 */
	RCU_INIT_POINTER(athrs_fast_nat_recv, NULL);

	/*
	 * Wait for all callbacks to complete.
	 */
	rcu_barrier();

	/*
	 * Destroy all connections.
	 */
	sfe_ipv4_destroy_all_rules_for_dev(NULL);

// XXX - this is where we need to unregister with any lower level offload services.

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &sfe_cm_conntrack_notifier);

#endif
	nf_unregister_hooks(sfe_cm_ipv4_ops_post_routing, ARRAY_SIZE(sfe_cm_ipv4_ops_post_routing));

	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);

	kobject_put(sc->sys_sfe_cm);

}

module_init(sfe_cm_init)
module_exit(sfe_cm_exit)

MODULE_AUTHOR("Qualcomm Atheros Inc.");
MODULE_DESCRIPTION("Shortcut Forwarding Engine - Connection Manager");
MODULE_LICENSE("Dual BSD/GPL");


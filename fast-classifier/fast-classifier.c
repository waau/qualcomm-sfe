/*
 * fast-classifier.c
 *	Shortcut forwarding engine connection manager.
 *	fast-classifier style
 *
 * XXX - fill in the appropriate GPL notice.
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
#include <net/genetlink.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ratelimit.h>
#include <linux/if_pppox.h>

#include "../shortcut-fe/sfe.h"
#include "../shortcut-fe/sfe_ipv4.h"
#include "fast-classifier.h"

/*
 * Per-module structure.
 */
struct fast_classifier {
	spinlock_t lock;		/* Lock for SMP correctness */

	/*
	 * Control state.
	 */
	struct kobject *sys_fast_classifier;	/* sysfs linkage */

	/*
	 * Callback notifiers.
	 */
	struct notifier_block dev_notifier;
					/* Device notifier */
	struct notifier_block inet_notifier;
					/* IP notifier */
};

struct fast_classifier __sc;

static struct nla_policy fast_classifier_genl_policy[FAST_CLASSIFIER_A_MAX + 1] = {
	[FAST_CLASSIFIER_A_TUPLE] = { .type = NLA_UNSPEC,
				      .len = sizeof(struct fast_classifier_tuple)
				    },
};

static struct genl_multicast_group fast_classifier_genl_mcgrp = {
	.name = FAST_CLASSIFIER_GENL_MCGRP,
};

static struct genl_family fast_classifier_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = FAST_CLASSIFIER_GENL_HDRSIZE,
	.name = FAST_CLASSIFIER_GENL_NAME,
	.version = FAST_CLASSIFIER_GENL_VERSION,
	.maxattr = FAST_CLASSIFIER_A_MAX,
};

static int fast_classifier_offload_genl_msg(struct sk_buff *skb, struct genl_info *info);

static struct genl_ops fast_classifier_gnl_ops[] = {
	{
		.cmd = FAST_CLASSIFIER_C_OFFLOAD,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = fast_classifier_offload_genl_msg,
		.dumpit = NULL,
	},
	{
		.cmd = FAST_CLASSIFIER_C_OFFLOADED,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = NULL,
		.dumpit = NULL,
	},
	{
		.cmd = FAST_CLASSIFIER_C_DONE,
		.flags = 0,
		.policy = fast_classifier_genl_policy,
		.doit = NULL,
		.dumpit = NULL,
	},
};

/*
 * Expose the hook for the receive processing.
 */
extern int (*athrs_fast_nat_recv)(struct sk_buff *skb);

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;

/*
 * fast_classifier_recv()
 *	Handle packet receives.
 *
 * Returns 1 if the packet is forwarded or 0 if it isn't.
 */
int fast_classifier_recv(struct sk_buff *skb)
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

	/*
	 * And PPPoE packets
	 */
	if (htons(ETH_P_PPP_SES) == skb->protocol) {
		return sfe_pppoe_recv(dev, skb);
        }

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

	DEBUG_TRACE("not IP or PPPoE packet\n");
	return 0;
}

/*
 * fast_classifier_find_mac_addr()
 *	Find the MAC address for a given IPv4 address.
 *
 * Returns true if we find the MAC address, otherwise false.
 *
 * We look up the rtable entry for the address and, from its neighbour
 * structure, obtain the hardware address.  This means this function also
 * works if the neighbours are routers too.
 */
static bool fast_classifier_find_mac_addr(uint32_t addr, uint8_t *mac_addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;
	struct net_device *dev;

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
	neigh = dst_get_neighbour_noref(dst);
	if (unlikely(!neigh)) {
		rcu_read_unlock();
		dst_release(dst);
		return false;
	}

	if (unlikely(!(neigh->nud_state & NUD_VALID))) {
		rcu_read_unlock();
		dst_release(dst);
		return false;
	}

	dev = neigh->dev;
	if (!dev) {
		rcu_read_unlock();
		dst_release(dst);
		return false;
	}

	memcpy(mac_addr, neigh->ha, (size_t)dev->addr_len);
	rcu_read_unlock();

	dst_release(dst);

	/*
	 * We're only interested in unicast MAC addresses - if it's not a unicast
	 * address then our IP address mustn't be unicast either.
	 */
	if (is_multicast_ether_addr(mac_addr)) {
		DEBUG_TRACE("MAC is non-unicast - ignoring\n");
		return false;
	}

	return true;
}

static DEFINE_SPINLOCK(sfe_connections_lock);

struct sfe_connection {
	struct list_head list;
	struct sfe_ipv4_create *sic;
	struct nf_conn *ct;
	int hits;
	int offloaded;
	unsigned char mac[ETH_ALEN];
};

static LIST_HEAD(sfe_connections);

/*
 * fast_classifier_update_protocol()
 * 	Update sfe_ipv4_create struct with new protocol information before we offload
 */
static int fast_classifier_update_protocol(struct sfe_ipv4_create *p_sic, struct nf_conn *ct)
{
	switch (p_sic->protocol) {
		case IPPROTO_TCP:
			p_sic->src_td_window_scale = ct->proto.tcp.seen[0].td_scale;
			p_sic->src_td_max_window = ct->proto.tcp.seen[0].td_maxwin;
			p_sic->src_td_end = ct->proto.tcp.seen[0].td_end;
			p_sic->src_td_max_end = ct->proto.tcp.seen[0].td_maxend;
			p_sic->dest_td_window_scale = ct->proto.tcp.seen[1].td_scale;
			p_sic->dest_td_max_window = ct->proto.tcp.seen[1].td_maxwin;
			p_sic->dest_td_end = ct->proto.tcp.seen[1].td_end;
			p_sic->dest_td_max_end = ct->proto.tcp.seen[1].td_maxend;
			if (nf_ct_tcp_no_window_check
			    || (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
			    || (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
				p_sic->flags |= SFE_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
			}

			/*
			 * If the connection is shutting down do not manage it.
			 * state can not be SYN_SENT, SYN_RECV because connection is assured
			 * Not managed states: FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE.
			 */
			spin_lock(&ct->lock);
			if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
				spin_unlock(&ct->lock);
				DEBUG_TRACE("connection in termination state: %#x, s: %pI4:%u, d: %pI4:%u\n",
					    ct->proto.tcp.state, &p_sic->src_ip, ntohs(p_sic->src_port),
					    &p_sic->dest_ip, ntohs(p_sic->dest_port));
				return 0;
			}
			spin_unlock(&ct->lock);
			break;

		case IPPROTO_UDP:
			break;

		default:
			DEBUG_TRACE("unhandled protocol %d\n", p_sic->protocol);
			return 0;
	}

	return 1;
}

/* fast_classifier_send_genl_msg()
 * 	Function to send a generic netlink message
 */
static void fast_classifier_send_genl_msg(int msg, struct fast_classifier_tuple *fc_msg) {
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL)
		return;

	msg_head = genlmsg_put(skb, 0, 0, &fast_classifier_gnl_family, 0, msg);
	if (msg_head == NULL) {
		nlmsg_free(skb);
		return;
	}

	rc = nla_put(skb, FAST_CLASSIFIER_A_TUPLE, sizeof(struct fast_classifier_tuple), fc_msg);
	if (rc != 0) {
		genlmsg_cancel(skb, msg_head);
		nlmsg_free(skb);
		return;
	}

	rc = genlmsg_end(skb, msg_head);
	if (rc < 0) {
		genlmsg_cancel(skb, msg_head);
		nlmsg_free(skb);
		return;
	}
	genlmsg_multicast(skb, 0, fast_classifier_genl_mcgrp.id, GFP_ATOMIC);

	DEBUG_TRACE("INFO: %d : %d, %pI4, %pI4, %d, %d MAC=%pM\n",
			msg, fc_msg->proto,
			&(fc_msg->src_saddr),
			&(fc_msg->dst_saddr),
			fc_msg->sport, fc_msg->dport,
			fc_msg->mac);
}

/*
 * fast_classifier_offload_genl_msg()
 * 	Called from user space to offload a connection
 */
static int fast_classifier_offload_genl_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct nlattr *na;
	struct fast_classifier_tuple *fc_msg;
	struct sfe_ipv4_create *p_sic;
	struct sfe_connection *conn;
	unsigned long flags;

	na = info->attrs[FAST_CLASSIFIER_A_TUPLE];
	fc_msg = nla_data(na);

	DEBUG_TRACE("INFO: want to offload: %d, %pI4, %pI4, %d, %d MAC=%pM\n",
			fc_msg->proto,
			&(fc_msg->src_saddr),
			&(fc_msg->dst_saddr),
			fc_msg->sport, fc_msg->dport,
			fc_msg->mac);

	spin_lock_irqsave(&sfe_connections_lock, flags);
	list_for_each_entry(conn, &sfe_connections, list) {
		p_sic = conn->sic;

		DEBUG_TRACE(" -> COMPARING: proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d...",
				p_sic->protocol, p_sic->src_ip, p_sic->dest_ip,
				p_sic->src_port, p_sic->dest_port);

		if (p_sic->protocol == fc_msg->proto &&
		    p_sic->src_port == fc_msg->sport &&
		    p_sic->dest_port == fc_msg->dport &&
		    p_sic->src_ip == fc_msg->src_saddr &&
		    p_sic->dest_ip == fc_msg->dst_saddr ) {
			if (conn->offloaded == 0) {
				DEBUG_TRACE("USERSPACE OFFLOAD REQUEST, MATCH FOUND, WILL OFFLOAD\n");
				if (fast_classifier_update_protocol(p_sic, conn->ct) == 0) {
					spin_unlock_irqrestore(&sfe_connections_lock, flags);
					DEBUG_TRACE("UNKNOWN PROTOCOL OR CONNECTION CLOSING, SKIPPING\n");
					return 0;
				}
				DEBUG_TRACE("INFO: calling sfe rule creation!\n");
				spin_unlock_irqrestore(&sfe_connections_lock, flags);
				ret = sfe_ipv4_create_rule(p_sic);
				if ((ret == 0) || (ret == -EADDRINUSE)) {
					conn->offloaded = 1;
					fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_OFFLOADED, fc_msg);
				}
				return 0;
			}
			/* conn->offloaded != 0 */
			DEBUG_TRACE("GOT REQUEST TO OFFLOAD ALREADY OFFLOADED CONN FROM USERSPACE\n");
			spin_unlock_irqrestore(&sfe_connections_lock, flags);
			return 0;
		}
		DEBUG_TRACE("SEARCH CONTINUES\n");
	}

	spin_unlock_irqrestore(&sfe_connections_lock, flags);
	return 0;
}

/* auto offload connection once we have this many packets*/
static int offload_at_pkts = 128;

/*
 * fast_classifier_ipv4_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
static unsigned int fast_classifier_ipv4_post_routing_hook(unsigned int hooknum,
						  struct sk_buff *skb,
						  const struct net_device *in_unused,
						  const struct net_device *out,
						  int (*okfn)(struct sk_buff *))
{
	int ret;
	struct sfe_ipv4_create sic;
	struct sfe_ipv4_create *p_sic;
	struct net_device *in;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	struct net_device *src_br_dev = NULL;
	struct net_device *dest_br_dev = NULL;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	struct sfe_connection *conn;
	int sfe_connections_size = 0;
	unsigned long flags;
	struct ethhdr *mh = eth_hdr(skb);

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
	if  (!in) {
		DEBUG_TRACE("packet not forwarding\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets with non-standard 802.3 MAC address sizes.
	 */
	if (unlikely(in->addr_len != ETH_ALEN)) {
		DEBUG_TRACE("in device: %s not 802.3 hw addr len: %u, ignoring\n",
				in->name, (unsigned)in->addr_len);
		goto done1;
	}
	if (unlikely(out->addr_len != ETH_ALEN)) {
		DEBUG_TRACE("out device: %s not 802.3 hw addr len: %u, ignoring\n",
				out->name, (unsigned)out->addr_len);
		goto done1;
	}

	/*
	 * Don't process packets that aren't being tracked by conntrack.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("no conntrack connection, ignoring\n");
		goto done1;
	}

	/*
	 * Don't process untracked connections.
	 */
	if (unlikely(ct == &nf_conntrack_untracked)) {
		DEBUG_TRACE("untracked connection\n");
		goto done1;
	}

	/*
	 * Don't process connections that require support from a 'helper' (typically a NAT ALG).
	 */
	if (unlikely(nfct_help(ct))) {
		DEBUG_TRACE("connection has helper\n");
		goto done1;
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

		/*
		 * Don't try to manage a non-established connection.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
			DEBUG_TRACE("non-established connection\n");
			goto done1;
		}

		break;

	case IPPROTO_UDP:
		sic.src_port = orig_tuple.src.u.udp.port;
		sic.dest_port = orig_tuple.dst.u.udp.port;
		sic.src_port_xlate = reply_tuple.dst.u.udp.port;
		sic.dest_port_xlate = reply_tuple.src.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol %d\n", sic.protocol);
		goto done1;
	}

	/*
	 * If we already have this connection in our list, skip it
	 * XXX: this may need to be optimized
	 */
	DEBUG_TRACE("POST_ROUTE: checking new connection: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d\n",
			sic.protocol, sic.src_ip, sic.dest_ip,
			sic.src_port, sic.dest_port);
	spin_lock_irqsave(&sfe_connections_lock, flags);
	list_for_each_entry(conn, &sfe_connections, list) {
		p_sic = conn->sic;
		DEBUG_TRACE("\t\t-> COMPARING: proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d...",
				p_sic->protocol, p_sic->src_ip, p_sic->dest_ip,
				p_sic->src_port, p_sic->dest_port);

		if (p_sic->protocol == sic.protocol &&
		    p_sic->src_port == sic.src_port &&
		    p_sic->dest_port == sic.dest_port &&
		    p_sic->src_ip == sic.src_ip &&
		    p_sic->dest_ip == sic.dest_ip ) {
			conn->hits++;
			if (conn->offloaded == 0) {
				if (conn->hits == offload_at_pkts) {
					struct fast_classifier_tuple fc_msg;
					DEBUG_TRACE("OFFLOADING CONNECTION, TOO MANY HITS\n");
					if (fast_classifier_update_protocol(p_sic, conn->ct) == 0) {
						spin_unlock_irqrestore(&sfe_connections_lock, flags);
						DEBUG_TRACE("UNKNOWN PROTOCOL OR CONNECTION CLOSING, SKIPPING\n");
						return 0;
					}
					DEBUG_TRACE("INFO: calling sfe rule creation!\n");
					spin_unlock_irqrestore(&sfe_connections_lock, flags);

					ret = sfe_ipv4_create_rule(p_sic);
					if ((ret == 0) || (ret == -EADDRINUSE)) {
						conn->offloaded = 1;
						fc_msg.proto = sic.protocol;
						fc_msg.src_saddr = sic.src_ip;
						fc_msg.dst_saddr = sic.dest_ip;
						fc_msg.sport = sic.src_port;
						fc_msg.dport = sic.dest_port;
						memcpy(fc_msg.mac, conn->mac, ETH_ALEN);
						fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_OFFLOADED, &fc_msg);
					}

					goto done1;
				} else if (conn->hits > offload_at_pkts) {
					DEBUG_ERROR("ERROR: MORE THAN %d HITS AND NOT OFFLOADED\n", offload_at_pkts);
					spin_unlock_irqrestore(&sfe_connections_lock, flags);
					goto done1;
				}
			}

			spin_unlock_irqrestore(&sfe_connections_lock, flags);
			if (conn->offloaded == 1) {
				sfe_ipv4_update_rule(p_sic);
			}

			DEBUG_TRACE("FOUND, SKIPPING\n");
			goto done1;
		}

		DEBUG_TRACE("SEARCH CONTINUES");
		sfe_connections_size++;
	}
	spin_unlock_irqrestore(&sfe_connections_lock, flags);

	/*
	 * Get the MAC addresses that correspond to source and destination host addresses.
	 */
	if (!fast_classifier_find_mac_addr(sic.src_ip, sic.src_mac)) {
		DEBUG_TRACE("failed to find MAC address for src IP: %pI4\n", &sic.src_ip);
		goto done1;
	}

	if (!fast_classifier_find_mac_addr(sic.src_ip_xlate, sic.src_mac_xlate)) {
		DEBUG_TRACE("failed to find MAC address for xlate src IP: %pI4\n", &sic.src_ip_xlate);
		goto done1;
	}

	/*
	 * Do dest now
	 */
	if (!fast_classifier_find_mac_addr(sic.dest_ip, sic.dest_mac)) {
		DEBUG_TRACE("failed to find MAC address for dest IP: %pI4\n", &sic.dest_ip);
		goto done1;
	}

	if (!fast_classifier_find_mac_addr(sic.dest_ip_xlate, sic.dest_mac_xlate)) {
		DEBUG_TRACE("failed to find MAC address for xlate dest IP: %pI4\n", &sic.dest_ip_xlate);
		goto done1;
	}

	/*
	 * Get our device info.  If we're dealing with the "reply" direction here then
	 * we'll need things swapped around.
	 */
	if (ctinfo < IP_CT_IS_REPLY) {
		src_dev = in;
		dest_dev = (struct net_device *)out;
	} else {
		src_dev = (struct net_device *)out;
		dest_dev = in;
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
			goto done1;
		}

		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_EBRIDGE) {
		dest_br_dev = br_port_dev_get(dest_dev, sic.dest_mac_xlate);
		if (!dest_br_dev) {
			DEBUG_TRACE("no port found on bridge\n");
			goto done2;
		}

		dest_dev = dest_br_dev;
	}
#else
	/*
	 * Our devices may actually be part of a bridge interface.  If that's
	 * the case then find the bridge interface instead.
	 */
	if (src_dev->priv_flags & IFF_BRIDGE_PORT) {
		src_br_dev = src_dev->master;
		if (!src_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", src_dev->name);
			goto done1;
		}

		dev_hold(src_br_dev);
		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_BRIDGE_PORT) {
		dest_br_dev = dest_dev->master;
		if (!dest_br_dev) {
			DEBUG_TRACE("no bridge found for: %s\n", dest_dev->name);
			goto done2;
		}

		dev_hold(dest_br_dev);
		dest_dev = dest_br_dev;
	}
#endif

	sic.src_dev = src_dev;
	sic.dest_dev = dest_dev;

// XXX - these MTUs need handling correctly!
	sic.src_mtu = 1500;
	sic.dest_mtu = 1500;

	if (skb->mark) {
		DEBUG_TRACE("SKB MARK NON ZERO %x\n", skb->mark);
	}
	sic.mark = skb->mark;

	if (last_pppox_sock && last_pppox_sock->pppoe_dev == in->name) {
		struct sock *sk = &last_pppox_sock->sk;

		if (sk->sk_family == PF_PPPOX && sk->sk_protocol == PX_PROTO_OE) {
			sic.dest_pppoe_sk = sk;
		}
	} else {
		sic.dest_pppoe_sk = NULL;
	}
	sic.src_pppoe_sk = NULL;

	conn = kmalloc(sizeof(struct sfe_connection), GFP_KERNEL);
	if (conn == NULL) {
		printk(KERN_CRIT "ERROR: no memory for sfe\n");
		goto done3;
	}
	conn->hits = 0;
	conn->offloaded = 0;
	DEBUG_TRACE("Source MAC=%pM\n", mh->h_source);
	memcpy(conn->mac, mh->h_source, ETH_ALEN);

	p_sic = kmalloc(sizeof(struct sfe_ipv4_create), GFP_KERNEL);
	if (p_sic == NULL) {
		printk(KERN_CRIT "ERROR: no memory for sfe\n");
		kfree(conn);
		goto done3;
	}

	memcpy(p_sic, &sic, sizeof(sic));
	conn->sic = p_sic;
	conn->ct = ct;
	DEBUG_TRACE(" -> adding item to sfe_connections, new size: %d\n", ++sfe_connections_size);
	DEBUG_TRACE("POST_ROUTE: new offloadable connection: proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d\n",
			p_sic->protocol, p_sic->src_ip, p_sic->dest_ip,
			p_sic->src_port, p_sic->dest_port);
	spin_lock_irqsave(&sfe_connections_lock, flags);
	list_add_tail(&(conn->list), &sfe_connections);
	spin_unlock_irqrestore(&sfe_connections_lock, flags);
done3:
	/*
	 * If we had bridge ports then release them too.
	 */
	if (dest_br_dev) {
		dev_put(dest_br_dev);
	}

done2:
	if (src_br_dev) {
		dev_put(src_br_dev);
	}

done1:
	/*
	 * Release the interface on which this skb arrived
	 */
	dev_put(in);

	return NF_ACCEPT;
}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * fast_classifier_conntrack_event()
 *	Callback event invoked when a conntrack connection's state changes.
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int fast_classifier_conntrack_event(struct notifier_block *this,
				unsigned int events, struct nf_ct_event *item)
#else
static int fast_classifier_conntrack_event(unsigned int events, struct nf_ct_event *item)
#endif
{
	struct sfe_ipv4_destroy sid;
	struct nf_conn *ct = item->ct;
	struct nf_conntrack_tuple orig_tuple;
	struct sfe_connection *conn;
	struct sfe_ipv4_create *p_sic;
	int sfe_found_match = 0;
	int sfe_connections_size = 0;
	unsigned long flags;
	struct fast_classifier_tuple fc_msg;

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
	 * Check for an updated mark
	 */
	if ((events & (1 << IPCT_MARK)) && (ct->mark != 0)) {
		struct sfe_ipv4_mark mark;
		orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

		mark.protocol = (int32_t)orig_tuple.dst.protonum;
		mark.src_ip = (__be32)orig_tuple.src.u3.ip;
		mark.dest_ip = (__be32)orig_tuple.dst.u3.ip;
		switch (mark.protocol) {
		case IPPROTO_TCP:
			mark.src_port = orig_tuple.src.u.tcp.port;
			mark.dest_port = orig_tuple.dst.u.tcp.port;
			break;
		case IPPROTO_UDP:
			mark.src_port = orig_tuple.src.u.udp.port;
			mark.dest_port = orig_tuple.dst.u.udp.port;
			break;
		default:
			break;
		}

		mark.mark = ct->mark;
		sfe_ipv4_mark_rule(&mark);
	}

	/*
	 * We're only interested in destroy events at this point
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

	/*
	 * If we already have this connection in our list, skip it
	 * XXX: this may need to be optimized
	 */
	DEBUG_TRACE("INFO: want to clean up: proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d\n",
			sid.protocol, sid.src_ip, sid.dest_ip,
			sid.src_port, sid.dest_port);
	spin_lock_irqsave(&sfe_connections_lock, flags);
	list_for_each_entry(conn, &sfe_connections, list) {
		p_sic = conn->sic;
		DEBUG_TRACE(" -> COMPARING: proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d...",
				p_sic->protocol, p_sic->src_ip, p_sic->dest_ip,
				p_sic->src_port, p_sic->dest_port);

		if (p_sic->protocol == sid.protocol &&
		    p_sic->src_port == sid.src_port &&
		    p_sic->dest_port == sid.dest_port &&
		    p_sic->src_ip == sid.src_ip &&
		    p_sic->dest_ip == sid.dest_ip ) {
			fc_msg.proto = p_sic->protocol;
			fc_msg.src_saddr = p_sic->src_ip;
			fc_msg.dst_saddr = p_sic->dest_ip;
			fc_msg.sport = p_sic->src_port;
			fc_msg.dport = p_sic->dest_port;
			memcpy(fc_msg.mac, conn->mac, ETH_ALEN);
			sfe_found_match = 1;
			DEBUG_TRACE("FOUND, DELETING\n");
			break;
		}
		DEBUG_TRACE("SEARCH CONTINUES\n");
		sfe_connections_size++;
	}

	if (sfe_found_match) {
		DEBUG_TRACE("INFO: connection over proto: %d src_ip: %d dst_ip: %d, src_port: %d, dst_port: %d\n",
				p_sic->protocol, p_sic->src_ip, p_sic->dest_ip,
				p_sic->src_port, p_sic->dest_port);
		kfree(conn->sic);
		list_del(&(conn->list));
		kfree(conn);
	} else {
		DEBUG_TRACE("NO MATCH FOUND IN %d ENTRIES!!\n", sfe_connections_size);
	}
	spin_unlock_irqrestore(&sfe_connections_lock, flags);

	sfe_ipv4_destroy_rule(&sid);

	if (sfe_found_match) {
		fast_classifier_send_genl_msg(FAST_CLASSIFIER_C_DONE, &fc_msg);
	}

	return NOTIFY_DONE;
}

/*
 * Netfilter conntrack event system to monitor connection tracking changes
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static struct notifier_block fast_classifier_conntrack_notifier = {
	.notifier_call = fast_classifier_conntrack_event,
};
#else
static struct nf_ct_event_notifier fast_classifier_conntrack_notifier = {
	.fcn = fast_classifier_conntrack_event,
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
static struct nf_hook_ops fast_classifier_ipv4_ops_post_routing[] __read_mostly = {
	{
		.hook = fast_classifier_ipv4_post_routing_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 1,
	},
};

/*
 * fast_classifier_sync_rule()
 *	Synchronize a connection's state.
 */
static void fast_classifier_sync_rule(struct sfe_ipv4_sync *sis)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	struct nf_conn_counter *acct;

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
		atomic64_set(&acct[IP_CT_DIR_ORIGINAL].packets, sis->src_packet_count);
		atomic64_set(&acct[IP_CT_DIR_ORIGINAL].bytes, sis->src_byte_count);
		atomic64_set(&acct[IP_CT_DIR_REPLY].packets, sis->dest_packet_count);
		atomic64_set(&acct[IP_CT_DIR_REPLY].bytes, sis->dest_byte_count);
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
 * fast_classifier_device_event()
 */
static int fast_classifier_device_event(struct notifier_block *this, unsigned long event, void *ptr)
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
 * fast_classifier_inet_event()
 */
static int fast_classifier_inet_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;
	return fast_classifier_device_event(this, event, dev);
}

/*
 * fast_classifier_get_offload_at_pkts()
 */
static ssize_t fast_classifier_get_offload_at_pkts(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return sprintf(buf, "%d\n", offload_at_pkts);
}

/*
 * fast_classifier_set_offload_at_pkts()
 */
static ssize_t fast_classifier_set_offload_at_pkts(struct device *dev,
					struct device_attribute *attr,
					char *buf, size_t size)
{
	long new;
	int ret;

	printk(KERN_EMERG "BUF: %s\n", buf);
	ret = strict_strtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	offload_at_pkts = new;

	return size;
}

/*
 * sysfs attributes.
 */
static const struct device_attribute fast_classifier_offload_at_pkts_attr =
	__ATTR(offload_at_pkts, S_IWUGO | S_IRUGO, fast_classifier_get_offload_at_pkts, fast_classifier_set_offload_at_pkts);

/*
 * fast_classifier_init()
 */
static int __init fast_classifier_init(void)
{
	struct fast_classifier *sc = &__sc;
	int result = -1;

	printk(KERN_ALERT "fast-classifier: starting up\n");
	DEBUG_INFO("SFE CM init\n");

	/*
	 * Create sys/fast_classifier
	 */
	sc->sys_fast_classifier = kobject_create_and_add("fast_classifier", NULL);
	if (!sc->sys_fast_classifier) {
		DEBUG_ERROR("failed to register fast_classifier\n");
		goto exit1;
	}

	result = sysfs_create_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register debug dev file: %d\n", result);
		goto exit2;
	}

	sc->dev_notifier.notifier_call = fast_classifier_device_event;
	sc->dev_notifier.priority = 1;
	register_netdevice_notifier(&sc->dev_notifier);

	sc->inet_notifier.notifier_call = fast_classifier_inet_event;
	sc->inet_notifier.priority = 1;
	register_inetaddr_notifier(&sc->inet_notifier);

	/*
	 * Register our netfilter hooks.
	 */
	result = nf_register_hooks(fast_classifier_ipv4_ops_post_routing, ARRAY_SIZE(fast_classifier_ipv4_ops_post_routing));
	if (result < 0) {
		DEBUG_ERROR("can't register nf post routing hook: %d\n", result);
		goto exit3;
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/*
	 * Register a notifier hook to get fast notifications of expired connections.
	 */
	result = nf_conntrack_register_notifier(&init_net, &fast_classifier_conntrack_notifier);
	if (result < 0) {
		DEBUG_ERROR("can't register nf notifier hook: %d\n", result);
		goto exit4;
	}
#endif

	result = genl_register_family(&fast_classifier_gnl_family);
	if (result != 0) {
		printk(KERN_CRIT "unable to register genl family\n");
		goto exit5;
	}

	result = genl_register_ops(&fast_classifier_gnl_family, fast_classifier_gnl_ops);
	if (result != 0) {
		printk(KERN_CRIT "unable to register ops\n");
		goto exit6;
	}

	result = genl_register_mc_group(&fast_classifier_gnl_family,
					&fast_classifier_genl_mcgrp);
	if (result != 0) {
		printk(KERN_CRIT "unable to register multicast group\n");
		goto exit6;
	}

	printk(KERN_ALERT "fast-classifier: registered\n");

	spin_lock_init(&sc->lock);

	/*
	 * Hook the receive path in the network stack.
	 */
	BUG_ON(athrs_fast_nat_recv != NULL);
	RCU_INIT_POINTER(athrs_fast_nat_recv, fast_classifier_recv);

	/*
	 * Hook the shortcut sync callback.
	 */
	sfe_ipv4_register_sync_rule_callback(fast_classifier_sync_rule);

	return 0;

exit6:
	genl_unregister_family(&fast_classifier_gnl_family);

exit5:
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &fast_classifier_conntrack_notifier);
#endif

exit4:
	nf_unregister_hooks(fast_classifier_ipv4_ops_post_routing, ARRAY_SIZE(fast_classifier_ipv4_ops_post_routing));

exit3:
	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);
	sysfs_remove_file(sc->sys_fast_classifier, &fast_classifier_offload_at_pkts_attr.attr);

exit2:
	kobject_put(sc->sys_fast_classifier);

exit1:
	return result;
}

/*
 * fast_classifier_exit()
 */
static void __exit fast_classifier_exit(void)
{
	struct fast_classifier *sc = &__sc;
	int result = -1;

	DEBUG_INFO("SFE CM exit\n");
	printk(KERN_ALERT "fast-classifier: shutting down\n");

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

	result = genl_unregister_ops(&fast_classifier_gnl_family, fast_classifier_gnl_ops);
	if (result != 0) {
		printk(KERN_CRIT "Unable to unreigster genl_ops\n");
	}

	result = genl_unregister_family(&fast_classifier_gnl_family);
	if (result != 0) {
		printk(KERN_CRIT "Unable to unreigster genl_family\n");
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &fast_classifier_conntrack_notifier);

#endif
	nf_unregister_hooks(fast_classifier_ipv4_ops_post_routing, ARRAY_SIZE(fast_classifier_ipv4_ops_post_routing));

	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);

	kobject_put(sc->sys_fast_classifier);
}

module_init(fast_classifier_init)
module_exit(fast_classifier_exit)

MODULE_AUTHOR("Qualcomm Atheros Inc.");
MODULE_DESCRIPTION("Shortcut Forwarding Engine - Connection Manager");
MODULE_LICENSE("GPL");


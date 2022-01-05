/*
 * sfe_ipv6_tcp.c
 *	Shortcut forwarding engine file for IPv6 TCP
 *
 * Copyright (c) 2015-2016, 2019-2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021,2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/etherdevice.h>
#include <linux/version.h>

#include "sfe_debug.h"
#include "sfe_api.h"
#include "sfe.h"
#include "sfe_flow_cookie.h"
#include "sfe_ipv6.h"
#include "sfe_pppoe.h"

/*
 * sfe_ipv6_process_tcp_option_sack()
 *	Parse TCP SACK option and update ack according
 */
static bool sfe_ipv6_process_tcp_option_sack(const struct tcphdr *th, const u32 data_offs,
					     u32 *ack)
{
	u32 length = sizeof(struct tcphdr);
	u8 *ptr = (u8 *)th + length;

	/*
	 * Ignore processing if TCP packet has only TIMESTAMP option.
	 */
	if (likely(data_offs == length + TCPOLEN_TIMESTAMP + 1 + 1)
	    && likely(ptr[0] == TCPOPT_NOP)
	    && likely(ptr[1] == TCPOPT_NOP)
	    && likely(ptr[2] == TCPOPT_TIMESTAMP)
	    && likely(ptr[3] == TCPOLEN_TIMESTAMP)) {
		return true;
	}

	/*
	 * TCP options. Parse SACK option.
	 */
	while (length < data_offs) {
		u8 size;
		u8 kind;

		ptr = (u8 *)th + length;
		kind = *ptr;

		/*
		 * NOP, for padding
		 * Not in the switch because to fast escape and to not calculate size
		 */
		if (kind == TCPOPT_NOP) {
			length++;
			continue;
		}

		if (kind == TCPOPT_SACK) {
			u32 sack = 0;
			u8 re = 1 + 1;

			size = *(ptr + 1);
			if ((size < (1 + 1 + TCPOLEN_SACK_PERBLOCK))
			    || ((size - (1 + 1)) % (TCPOLEN_SACK_PERBLOCK))
			    || (size > (data_offs - length))) {
				return false;
			}

			re += 4;
			while (re < size) {
				u32 sack_re;
				u8 *sptr = ptr + re;
				sack_re = (sptr[0] << 24) | (sptr[1] << 16) | (sptr[2] << 8) | sptr[3];
				if (sack_re > sack) {
					sack = sack_re;
				}
				re += TCPOLEN_SACK_PERBLOCK;
			}
			if (sack > *ack) {
				*ack = sack;
			}
			length += size;
			continue;
		}
		if (kind == TCPOPT_EOL) {
			return true;
		}
		size = *(ptr + 1);
		if (size < 2) {
			return false;
		}
		length += size;
	}

	return true;
}

/*
 * sfe_ipv6_recv_tcp()
 *	Handle TCP packet receives and forwarding.
 */
int sfe_ipv6_recv_tcp(struct sfe_ipv6 *si, struct sk_buff *skb, struct net_device *dev,
			     unsigned int len, struct ipv6hdr *iph, unsigned int ihl, bool flush_on_find, struct sfe_l2_info *l2_info)
{
	struct tcphdr *tcph;
	struct sfe_ipv6_addr *src_ip;
	struct sfe_ipv6_addr *dest_ip;
	__be16 src_port;
	__be16 dest_port;
	struct sfe_ipv6_connection_match *cm;
	struct sfe_ipv6_connection_match *counter_cm;
	u32 flags;
	struct net_device *xmit_dev;
	bool ret;
	bool hw_csum;
	bool bridge_flow;

	/*
	 * Is our packet too short to contain a valid UDP header?
	 */
	if (!pskb_may_pull(skb, (sizeof(struct tcphdr) + ihl))) {

		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_HEADER_INCOMPLETE);
		DEBUG_TRACE("packet too short for TCP header\n");
		return 0;
	}

	/*
	 * Read the IP address and port information.  Read the IP header data first
	 * because we've almost certainly got that in the cache.  We may not yet have
	 * the TCP header cached though so allow more time for any prefetching.
	 */
	src_ip = (struct sfe_ipv6_addr *)iph->saddr.s6_addr32;
	dest_ip = (struct sfe_ipv6_addr *)iph->daddr.s6_addr32;

	tcph = (struct tcphdr *)(skb->data + ihl);
	src_port = tcph->source;
	dest_port = tcph->dest;
	flags = tcp_flag_word(tcph);

	rcu_read_lock();

	/*
	 * Look for a connection match.
	 */
#ifdef CONFIG_NF_FLOW_COOKIE
	cm = si->sfe_flow_cookie_table[skb->flow_cookie & SFE_FLOW_COOKIE_MASK].match;
	if (unlikely(!cm)) {
		cm = sfe_ipv6_find_connection_match_rcu(si, dev, IPPROTO_TCP, src_ip, src_port, dest_ip, dest_port);
	}
#else
	cm = sfe_ipv6_find_connection_match_rcu(si, dev, IPPROTO_TCP, src_ip, src_port, dest_ip, dest_port);
#endif
	if (unlikely(!cm)) {
		/*
		 * We didn't get a connection but as TCP is connection-oriented that
		 * may be because this is a non-fast connection (not running established).
		 * For diagnostic purposes we differentiate this here.
		 */
		if (likely((flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK)) == TCP_FLAG_ACK)) {
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_NO_CONNECTION_FAST_FLAGS);

			DEBUG_TRACE("no connection found - fast flags\n");
			return 0;
		}

		rcu_read_unlock();

		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_NO_CONNECTION_SLOW_FLAGS);
		DEBUG_TRACE("no connection found - slow flags: 0x%x\n",
			    flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK));
		return 0;
	}

	/*
	 * If our packet has beern marked as "flush on find" we can't actually
	 * forward it in the fast path, but now that we've found an associated
	 * connection we can flush that out before we process the packet.
	 */
	if (unlikely(flush_on_find)) {
		struct sfe_ipv6_connection *c = cm->connection;
		spin_lock_bh(&si->lock);
		ret = sfe_ipv6_remove_connection(si, c);
		spin_unlock_bh(&si->lock);

		DEBUG_TRACE("flush on find\n");
		if (ret) {
			sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
		}
		rcu_read_unlock();

		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_IP_OPTIONS_OR_INITIAL_FRAGMENT);
		return 0;
	}

#ifdef CONFIG_XFRM
	/*
	 * We can't accelerate the flow on this direction, just let it go
	 * through the slow path.
	 */
	if (unlikely(!cm->flow_accel)) {
		rcu_read_unlock();
		this_cpu_inc(si->stats_pcpu->packets_not_forwarded64);
		return 0;
	}
#endif

	bridge_flow = !!(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_BRIDGE_FLOW);

	/*
	 * Does our hop_limit allow forwarding?
	 */
	if (likely(!bridge_flow)) {
		if (unlikely(iph->hop_limit < 2)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("hop_limit too low\n");
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_SMALL_TTL);
			return 0;
		}
	}

	/*
	 * If our packet is larger than the MTU of the transmit interface then
	 * we can't forward it easily.
	 */
	if (unlikely((len > cm->xmit_dev_mtu) && !skb_is_gso(skb))) {
		struct sfe_ipv6_connection *c = cm->connection;
		spin_lock_bh(&si->lock);
		ret = sfe_ipv6_remove_connection(si, c);
		spin_unlock_bh(&si->lock);

		DEBUG_TRACE("larger than mtu\n");
		if (ret) {
			sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
		}
		rcu_read_unlock();

		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_NEEDS_FRAGMENTATION);
		return 0;
	}

	/*
	 * Look at our TCP flags.  Anything missing an ACK or that has RST, SYN or FIN
	 * set is not a fast path packet.
	 */
	if (unlikely((flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK)) != TCP_FLAG_ACK)) {
		struct sfe_ipv6_connection *c = cm->connection;
		spin_lock_bh(&si->lock);
		ret = sfe_ipv6_remove_connection(si, c);
		spin_unlock_bh(&si->lock);

		DEBUG_TRACE("TCP flags: 0x%x are not fast\n",
			    flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK));
		if (ret) {
			sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
		}
		rcu_read_unlock();

		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_FLAGS);
		return 0;
	}

	counter_cm = cm->counter_match;

	/*
	 * Are we doing sequence number checking?
	 */
	if (likely(!(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_NO_SEQ_CHECK))) {
		u32 seq;
		u32 ack;
		u32 sack;
		u32 data_offs;
		u32 end;
		u32 left_edge;
		u32 scaled_win;
		u32 max_end;

		/*
		 * Is our sequence fully past the right hand edge of the window?
		 */
		seq = ntohl(tcph->seq);
		if (unlikely((s32)(seq - (cm->protocol_state.tcp.max_end + 1)) > 0)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("seq: %u exceeds right edge: %u\n",
				    seq, cm->protocol_state.tcp.max_end + 1);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_SEQ_EXCEEDS_RIGHT_EDGE);
			return 0;
		}

		/*
		 * Check that our TCP data offset isn't too short.
		 */
		data_offs = tcph->doff << 2;
		if (unlikely(data_offs < sizeof(struct tcphdr))) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("TCP data offset: %u, too small\n", data_offs);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_SMALL_DATA_OFFS);
			return 0;
		}

		/*
		 * Update ACK according to any SACK option.
		 */
		ack = ntohl(tcph->ack_seq);
		sack = ack;
		if (unlikely(!sfe_ipv6_process_tcp_option_sack(tcph, data_offs, &sack))) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("TCP option SACK size is wrong\n");
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_BAD_SACK);
			return 0;
		}

		/*
		 * Check that our TCP data offset isn't past the end of the packet.
		 */
		data_offs += sizeof(struct ipv6hdr);
		if (unlikely(len < data_offs)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("TCP data offset: %u, past end of packet: %u\n",
				    data_offs, len);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_BIG_DATA_OFFS);
			return 0;
		}

		end = seq + len - data_offs;

		/*
		 * Is our sequence fully before the left hand edge of the window?
		 */
		if (unlikely((s32)(end - (cm->protocol_state.tcp.end
						- counter_cm->protocol_state.tcp.max_win - 1)) < 0)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("seq: %u before left edge: %u\n",
				    end, cm->protocol_state.tcp.end - counter_cm->protocol_state.tcp.max_win - 1);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_SEQ_BEFORE_LEFT_EDGE);
			return 0;
		}

		/*
		 * Are we acking data that is to the right of what has been sent?
		 */
		if (unlikely((s32)(sack - (counter_cm->protocol_state.tcp.end + 1)) > 0)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("ack: %u exceeds right edge: %u\n",
				    sack, counter_cm->protocol_state.tcp.end + 1);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_ACK_EXCEEDS_RIGHT_EDGE);
			return 0;
		}

		/*
		 * Is our ack too far before the left hand edge of the window?
		 */
		left_edge = counter_cm->protocol_state.tcp.end
			    - cm->protocol_state.tcp.max_win
			    - SFE_IPV6_TCP_MAX_ACK_WINDOW
			    - 1;
		if (unlikely((s32)(sack - left_edge) < 0)) {
			struct sfe_ipv6_connection *c = cm->connection;
			spin_lock_bh(&si->lock);
			ret = sfe_ipv6_remove_connection(si, c);
			spin_unlock_bh(&si->lock);

			DEBUG_TRACE("ack: %u before left edge: %u\n", sack, left_edge);
			if (ret) {
				sfe_ipv6_flush_connection(si, c, SFE_SYNC_REASON_FLUSH);
			}
			rcu_read_unlock();

			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_TCP_ACK_BEFORE_LEFT_EDGE);
			return 0;
		}

		/*
		 * Have we just seen the largest window size yet for this connection?  If yes
		 * then we need to record the new value.
		 */
		scaled_win = ntohs(tcph->window) << cm->protocol_state.tcp.win_scale;
		scaled_win += (sack - ack);
		if (unlikely(cm->protocol_state.tcp.max_win < scaled_win)) {
			cm->protocol_state.tcp.max_win = scaled_win;
		}

		/*
		 * If our sequence and/or ack numbers have advanced then record the new state.
		 */
		if (likely((s32)(end - cm->protocol_state.tcp.end) >= 0)) {
			cm->protocol_state.tcp.end = end;
		}

		max_end = sack + scaled_win;
		if (likely((s32)(max_end - counter_cm->protocol_state.tcp.max_end) >= 0)) {
			counter_cm->protocol_state.tcp.max_end = max_end;
		}
	}

	/*
	 * For PPPoE packets, match server MAC and session id
	 */
	if (unlikely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_PPPOE_DECAP)) {
		struct pppoe_hdr *ph;
		struct ethhdr *eth;

		if (unlikely(!l2_info) || unlikely(!sfe_l2_parse_flag_check(l2_info, SFE_L2_PARSE_FLAGS_PPPOE_INGRESS))) {
			rcu_read_unlock();
			DEBUG_TRACE("%px: PPPoE is not parsed\n", skb);
			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_INVALID_PPPOE_SESSION);
			return 0;
		}

		ph = (struct pppoe_hdr *)(skb->head + sfe_l2_pppoe_hdr_offset_get(l2_info));
		eth = (struct ethhdr *)(skb->head + sfe_l2_hdr_offset_get(l2_info));

		if (unlikely(cm->pppoe_session_id != htons(ph->sid)) || unlikely(!(ether_addr_equal((u8*)cm->pppoe_remote_mac, (u8 *)eth->h_source)))) {
			rcu_read_unlock();
			DEBUG_TRACE("%px: PPPoE sessions did not match \n", skb);
			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_INVALID_PPPOE_SESSION);
			return 0;
		}
		this_cpu_inc(si->stats_pcpu->pppoe_decap_packets_forwarded64);

	} else if (unlikely(l2_info) && unlikely(sfe_l2_parse_flag_check(l2_info, SFE_L2_PARSE_FLAGS_PPPOE_INGRESS))) {

		/*
		 * If packet contains PPPOE header but CME doesn't contain PPPoE flag yet we are exceptioning the packet to linux
		 */
		rcu_read_unlock();
		DEBUG_TRACE("%px: CME doesn't contain PPPOE flag but packet has PPPoE header\n", skb);
		sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_PPPOE_NOT_SET_IN_CME);
		return 0;
	}

	/*
	 * From this point on we're good to modify the packet.
	 */

	/*
	 * Check if skb was cloned. If it was, unshare it. Because
	 * the data area is going to be written in this path and we don't want to
	 * change the cloned skb's data section.
	 */
	if (unlikely(skb_cloned(skb))) {
		DEBUG_TRACE("%px: skb is a cloned skb\n", skb);
		skb = skb_unshare(skb, GFP_ATOMIC);
                if (!skb) {
			DEBUG_WARN("Failed to unshare the cloned skb\n");
			rcu_read_unlock();
			return 0;
		}

		/*
		 * Update the iph and tcph pointers with the unshared skb's data area.
		 */
		iph = (struct ipv6hdr *)skb->data;
		tcph = (struct tcphdr *)(skb->data + ihl);
	}

	/*
	 * For PPPoE flows, add PPPoE header before L2 header is added.
	 */
	if (cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_PPPOE_ENCAP) {
		if (unlikely(!sfe_pppoe_add_header(skb, cm->pppoe_session_id, PPP_IPV6))) {
			rcu_read_unlock();
			DEBUG_WARN("%px: PPPoE header addition failed\n", skb);
			sfe_ipv6_exception_stats_inc(si, SFE_IPV6_EXCEPTION_EVENT_PPPOE_HEADER_ENCAP_FAILED);
			return 0;
		}
		this_cpu_inc(si->stats_pcpu->pppoe_encap_packets_forwarded64);
	}

	/*
	 * TODO: VLAN header should be added here when they are supported.
	 */

	/*
	 * Update DSCP
	 */
	if (unlikely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_DSCP_REMARK)) {
		sfe_ipv6_change_dsfield(iph, cm->dscp);
	}

	/*
	 * Decrement our hop_limit.
	 */
	if (likely(!bridge_flow)) {
		iph->hop_limit -= 1;
	}

	/*
	 * Enable HW csum if rx checksum is verified and xmit interface is CSUM offload capable.
	 * Note: If L4 csum at Rx was found to be incorrect, we (router) should use incremental L4 checksum here
	 * so that HW does not re-calculate/replace the L4 csum
	 */
	hw_csum = !!(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_CSUM_OFFLOAD) && (skb->ip_summed == CHECKSUM_UNNECESSARY);

	/*
	 * Do we have to perform translations of the source address/port?
	 */
	if (unlikely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_XLATE_SRC)) {
		u16 tcp_csum;
		u32 sum;

		iph->saddr.s6_addr32[0] = cm->xlate_src_ip[0].addr[0];
		iph->saddr.s6_addr32[1] = cm->xlate_src_ip[0].addr[1];
		iph->saddr.s6_addr32[2] = cm->xlate_src_ip[0].addr[2];
		iph->saddr.s6_addr32[3] = cm->xlate_src_ip[0].addr[3];
		tcph->source = cm->xlate_src_port;

		if (unlikely(!hw_csum)) {
			tcp_csum = tcph->check;
			sum = tcp_csum + cm->xlate_src_csum_adjustment;
			sum = (sum & 0xffff) + (sum >> 16);
			tcph->check = (u16)sum;
		}
	}

	/*
	 * Do we have to perform translations of the destination address/port?
	 */
	if (unlikely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_XLATE_DEST)) {
		u16 tcp_csum;
		u32 sum;

		iph->daddr.s6_addr32[0] = cm->xlate_dest_ip[0].addr[0];
		iph->daddr.s6_addr32[1] = cm->xlate_dest_ip[0].addr[1];
		iph->daddr.s6_addr32[2] = cm->xlate_dest_ip[0].addr[2];
		iph->daddr.s6_addr32[3] = cm->xlate_dest_ip[0].addr[3];
		tcph->dest = cm->xlate_dest_port;

		if (unlikely(!hw_csum)) {
			tcp_csum = tcph->check;
			sum = tcp_csum + cm->xlate_dest_csum_adjustment;
			sum = (sum & 0xffff) + (sum >> 16);
			tcph->check = (u16)sum;
		}
	}

	/*
	 * If HW checksum offload is not possible, incremental L4 checksum is used to update the packet.
	 * Setting ip_summed to CHECKSUM_UNNECESSARY ensures checksum is not recalculated further in packet
	 * path.
	 */
	if (likely(hw_csum)) {
		skb->ip_summed = CHECKSUM_PARTIAL;
	} else {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	/*
	 * Update traffic stats.
	 */
	atomic_inc(&cm->rx_packet_count);
	atomic_add(len, &cm->rx_byte_count);

	xmit_dev = cm->xmit_dev;
	skb->dev = xmit_dev;

	/*
	 * Check to see if we need to write a header.
	 */
	if (likely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_WRITE_L2_HDR)) {
		if (unlikely(!(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_WRITE_FAST_ETH_HDR))) {
			dev_hard_header(skb, xmit_dev, ETH_P_IPV6,
					cm->xmit_dest_mac, cm->xmit_src_mac, len);
		} else {
			/*
			 * For the simple case we write this really fast.
			 */
			struct ethhdr *eth = (struct ethhdr *)__skb_push(skb, ETH_HLEN);

			eth->h_proto = htons(ETH_P_IPV6);
			ether_addr_copy((u8 *)eth->h_dest, (u8 *)cm->xmit_dest_mac);
			ether_addr_copy((u8 *)eth->h_source, (u8 *)cm->xmit_src_mac);
		}
	}

	/*
	 * Update priority of skb.
	 */
	if (unlikely(cm->flags & SFE_IPV6_CONNECTION_MATCH_FLAG_PRIORITY_REMARK)) {
		skb->priority = cm->priority;
	}

	/*
	 * Mark outgoing packet
	 */
	skb->mark = cm->connection->mark;
	if (skb->mark) {
		DEBUG_TRACE("SKB MARK is NON ZERO %x\n", skb->mark);
	}

	rcu_read_unlock();

	this_cpu_inc(si->stats_pcpu->packets_forwarded64);

	/*
	 * We're going to check for GSO flags when we transmit the packet so
	 * start fetching the necessary cache line now.
	 */
	prefetch(skb_shinfo(skb));

	/*
	 * Mark that this packet has been fast forwarded.
	 */
	skb->fast_forwarded = 1;

	/*
	 * Send the packet on its way.
	 */
	dev_queue_xmit(skb);

	return 1;
}

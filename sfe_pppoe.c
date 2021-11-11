/*
 * sfe_pppoe.c
 *     API for shortcut forwarding engine PPPoE flows
 *
 * Copyright (c) 2021 Qualcomm Innovation Center, Inc. All rights reserved.
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
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>

#include "sfe_debug.h"
#include "sfe_api.h"
#include "sfe.h"
#include "sfe_pppoe.h"

#define SFE_PPPOE_HEADER_SIZE (sizeof(struct pppoe_hdr) + 2)

/*
 * sfe_pppoe_add_header()
 *	Add PPPoE header.
 *
 * skb->data will point to PPPoE header after the function
 */
int sfe_pppoe_add_header(struct sk_buff *skb, u16 pppoe_session_id, u16 ppp_protocol)
{
	u16 *l2_header;
	struct pppoe_hdr *ph;
	u16 *l3_header = (u16 *)skb->data;

	/*
	 * Check that we have space for PPPoE header and PPP header (2 bytes)
	 */
	if (unlikely(!pskb_may_pull(skb, SFE_PPPOE_HEADER_SIZE))) {
		DEBUG_TRACE("%px: Not enough headroom for PPPoE header \n", skb);
		return 0;
	}

	/*
	 * PPPoE header (8 bytes) + PPP header (2 bytes)
	 *
	 * Hence move by 10 bytes to accomodate PPPoE header
	 */
	l2_header = l3_header - (SFE_PPPOE_HEADER_SIZE / 2);

	/*
	 * Headers in skb will look like in below sequence
	 *	| PPPoE hdr(10 bytes) | L3 hdr |
	 */
	ph = (struct pppoe_hdr *)l2_header;
	ph->ver = 1;
	ph->type = 1;
	ph->code = 0;
	ph->sid = pppoe_session_id;
	ph->length = skb->len;
	skb->protocol = cpu_to_be16(ETH_P_PPP_SES);

	/*
	 * Insert the PPP header protocol
	 */
	*(l2_header + 4) = ppp_protocol;

	/*
	 * L2 header offset will point to PPPoE header,
	 * since sfe_ipv4_recv_tcp/udp() does skb_push by ETH_HLEN before adding L2 header.
	 */
	__skb_push(skb, SFE_PPPOE_HEADER_SIZE);

	return 1;
}

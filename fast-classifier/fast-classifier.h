/*
 * User space header to send message to the fast classifier
 */

void fast_classifier_ipv4_offload(unsigned char proto, unsigned long src_saddr,
					 unsigned long dst_saddr, unsigned short sport,
					 unsigned short dport);

void fast_classifier_listen_for_messages(void);

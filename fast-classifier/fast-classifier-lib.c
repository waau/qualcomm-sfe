#include <netlink/genl/genl.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "fast-classifier-priv.h"


void fast_classifier_ipv4_offload(unsigned char proto, unsigned long src_saddr,
					 unsigned long dst_saddr, unsigned short sport,
					 unsigned short dport) {
	struct nl_sock *sock;
	struct nl_msg *msg;
	int family;
	int ret;
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	struct fast_classifier_msg fc_msg;

#ifdef DEBUG
	printf("DEBUG: would offload: %d, %s, %s, %d, %d\n", proto,
				inet_ntop(AF_INET, &src_saddr,  src_str, INET_ADDRSTRLEN),
				inet_ntop(AF_INET, &dst_saddr,  dst_str, INET_ADDRSTRLEN),
				sport, dport);
#endif

	fc_msg.proto = proto;
	fc_msg.src_saddr = src_saddr;
	fc_msg.dst_saddr = dst_saddr;
	fc_msg.sport = sport;
	fc_msg.dport = dport;

        sock = nl_socket_alloc();
	if (sock == NULL) {
		printf("Unable to allocate socket.\n");
		return;
	}

	genl_connect(sock);

	family = genl_ctrl_resolve(sock, "FAST_CLASSIFIER");
	if (family < 0) {
		nl_socket_free(sock);
		printf("Unable to resolve family\n");
		return;
	}

	msg = nlmsg_alloc();
	if (msg == NULL) {
		nl_socket_free(sock);
		printf("Unable to allocate message\n");
		return;
	}

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0,
                    NLM_F_REQUEST, 1, 1);
        nla_put(msg, 1, sizeof(fc_msg), &fc_msg);

        ret = nl_send_auto_complete(sock, msg);

        nlmsg_free(msg);
        if (ret < 0) {
                printf("nlmsg_free failed");
		nl_close(sock);
		nl_socket_free(sock);
                return;
        }

        ret = nl_wait_for_ack(sock);
        if (ret < 0) {
                printf("wait for ack failed");
		nl_close(sock);
		nl_socket_free(sock);
                return;
        }

        nl_close(sock);
        nl_socket_free(sock);
}

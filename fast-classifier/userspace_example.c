#include <netlink/genl/genl.h>
#include <errno.h>

int main(int argc, char *argv[])
{
        struct nl_sock *sock;
	struct nl_msg *msg;
	int family;
	int ret;
	const char *txt = "Hello World";

        sock = nl_socket_alloc();
	if (sock == NULL) {
		printf("Unable to allocation socket.\n");
		return -ENOMEM;
	}

	genl_connect(sock);

	family = genl_ctrl_resolve(sock, "FAST_CLASSIFIER");
	if (family < 0) {
		printf("Unable to resolve family\n");
		return -ENOENT;
	}

	msg = nlmsg_alloc();
	if (msg == NULL) {
		printf("Unable to allocate message\n");
		return -ENOMEM;
	}

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0,
                    NLM_F_REQUEST, 1, 1);
        nla_put_string(msg, 1, txt);

        ret = nl_send_auto_complete(sock, msg);

        nlmsg_free(msg);
        if (ret < 0) {
                printf("nlmsg_free failed");
                return errno;
        }

        ret = nl_wait_for_ack(sock);
        if (ret < 0) {
                printf("wait for ack failed");
                return errno;
        }

        nl_close(sock);
        nl_socket_free(sock);

        return 0;
}

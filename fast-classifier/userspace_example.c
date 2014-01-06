#include <fast-classifier.h>

int main(int argc, char *argv[])
{
	if (fast_classifier_init() < 0) {
		printf("Unable to init generic netlink\n");
		exit(1);
	}

	fast_classifier_ipv4_offload('a', 0, 0, 0, 0);

	/* this never returns */
	fast_classifier_listen_for_messages();

	fast_classifier_close();

        return 0;
}

enum {
	FAST_CLASSIFIER_A_UNSPEC,
	FAST_CLASSIFIER_A_MSG,
	__FAST_CLASSIFIER_A_MAX,
};
#define FAST_CLASSIFIER_A_MAX (__FAST_CLASSIFIER_A_MAX - 1)

enum {
	FAST_CLASSIFIER_C_UNSPEC,
	FAST_CLASSIFIER_C_RECV,
	__FAST_CLASSIFIER_C_MAX,
};

struct fast_classifier_msg {
	unsigned char proto;
	unsigned long src_saddr;
	unsigned long dst_saddr;
	unsigned short sport;
	unsigned short dport;
};

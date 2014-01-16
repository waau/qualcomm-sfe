/*
 * sfe.h
 *	Shortcut forwarding engine.
 *
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * Select whether we "hook" in below or above the Ethernet bridge layer.
 *
 * XXX - note that hooking below the bridge (set this value to 0) will
 * not currently work completely cleanly within Linux.  In order to make
 * this work properly we need to resync stats to Linux.  Arguably if we
 * want to do this we also need to validate that the source MAC address
 * of any packets is actually correct too.  Right now we're relying on
 * the bridge layer to do this sort of thing for us.
 */
#define SFE_HOOK_ABOVE_BRIDGE 1

/*
 * Debug output verbosity level.
 */
#define DEBUG_LEVEL 2

#if (DEBUG_LEVEL < 1)
#define DEBUG_ERROR(s, ...)
#else
#define DEBUG_ERROR(s, ...) \
	printk("%s[%u]: ERROR:", __FILE__, __LINE__); \
	printk(s, ##__VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 2)
#define DEBUG_WARN(s, ...)
#else
#define DEBUG_WARN(s, ...) \
	printk("%s[%u]: WARN:", __FILE__, __LINE__); \
	printk(s, ##__VA_ARGS__);
#endif

#if (DEBUG_LEVEL < 3)
#define DEBUG_INFO(s, ...)
#else
#define DEBUG_INFO(s, ...) \
	printk("%s[%u]: INFO:", __FILE__, __LINE__); \
	printk(s, ##__VA_ARGS__);
#endif

#if (DEBUG_LEVEL < 4)
#define DEBUG_TRACE(s, ...)
#else
#define DEBUG_TRACE(s, ...) \
	printk("%s[%u]: TRACE:", __FILE__, __LINE__); \
	printk(s, ##__VA_ARGS__);
#endif



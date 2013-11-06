/*
 *  Copyright (C) 2013 Matthew McClintock <mmcclint@codeaurora.org>
 */

#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
	printk(KERN_ALERT "Hello\n");

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_ALERT "Goodbye world\n");
}

MODULE_LICENSE("GPL");


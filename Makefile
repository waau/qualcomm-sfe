# Makefile for the sfe modules

ccflags-y := -I$(obj) -I$(obj)/..


obj-$(simulated-driver)+= simulated-driver/
obj-$(shortcut-fe)+=shortcut-fe/

obj ?= .

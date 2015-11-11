#!/bin/sh

sudo rmmod cow_mem
sudo insmod cow_mem.ko
gcc ioctl.c
./a.out

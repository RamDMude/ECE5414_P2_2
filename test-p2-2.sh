#!/bin/bash

sudo insmod p2_part2.ko
cat /proc/perftop
cat /proc/perftop
cat /proc/perftop
sudo rmmod p2_part2.ko
# sudo dmesg | tail -n 9
sudo dmesg


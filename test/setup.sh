#!/bin/sh

REAL_IF=wlp0s20f3
VIRT_IF=vlan1

sudo ip link add $VIRT_IF link $REAL_IF type macvlan mode bridge
sudo ifconfig $VIRT_IF up

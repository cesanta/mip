#!/bin/sh

REAL_IF=wlp0s20f3
EXT_IF=enx8049710fcdd0
VIRT_IF=vlan1

mke() {
  sudo ifconfig $EXT_IF 10.1/24
  sudo route add default gw 192.168.0.1 $EXT_IF
}

rme() {
#  sudo ip link del bond0
  route del default gw 192.168.0.1 $EXT_IF
}

rundhcp() {
  sudo dhcpd --no-pid -f -d -lf /dev/null #-cf /tmp/dhcpd.conf
}

mkbr() {
  sudo ip link add name br0 type bridge
  sudo ip link set dev br0 up
  sudo ip link set dev $REAL_IF master br0
  sudo ip link set dev $EXT_IF master br0
}

rmbr() {
  sudo ip link set dev $REAL_IF nomaster
  sudo ip link set dev $EXT_IF nomaster
  sudo ip link del br0
}

mkvirt() {
  sudo ip link delete $VIRT_IF
  sudo ip link add $VIRT_IF link $REAL_IF type macvlan mode source
  sudo ifconfig $VIRT_IF 10.0.0.1/24 up
  sudo ip route add 10.0.0.0/24 via 10.0.0.1
}


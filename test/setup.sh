#!/bin/sh

REAL_IF=wlp0s20f3
VIRT_IF=vlan1

sudo ip link delete $VIRT_IF
sudo ip link add $VIRT_IF link $REAL_IF type macvlan mode source
#sudo ip link add $VIRT_IF link $REAL_IF type ipvlan
#sudo ip link add $VIRT_IF type dummy
sudo ifconfig $VIRT_IF 10.0.0.1/24 up
sudo ip route add 10.0.0.0/24 via 10.0.0.1

cat << EOF > dhcpd.conf
subnet 10.0.0.0 netmask 255.255.255.0 {
  range 10.0.0.2 10.0.0.254;
  option routers 10.0.0.1;
}
EOF
sudo dhcpd --no-pid -f -d -lf /dev/null #-cf /tmp/dhcpd.conf

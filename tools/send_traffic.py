#!/usr/bin/python2.7

import sys
import string
import threading
from scapy.all import *

def send_traffic(packet_count=1, length=100, src_mac=None, src_ip=None, ifc='eth0'):
    if src_mac is None:
        src_mac = get_if_hwaddr(ifc)
    if src_ip is None:
        src_ip = get_if_addr(ifc)

    data = "X" * (length-24-10)
    packet = Ether(src=src_mac)/IP(src=src_ip)/Raw(data)
    sendp(packet, iface=ifc, count=packet_count, verbose=0)
    print(packet_count)

def main():
    # threading.Timer(1.0, main).start()
    send_traffic(11, src_ip="10.0.0.0")
    send_traffic( 1, src_ip="10.0.0.1")
    send_traffic( 5, src_ip="10.0.0.2")
    send_traffic( 2, src_ip="10.0.0.3")
    send_traffic( 9, src_ip="10.0.0.4")
    send_traffic( 3, src_ip="10.0.0.5")
    send_traffic( 5, src_ip="10.0.0.6")
    send_traffic( 4, src_ip="10.0.0.7")

if __name__ == '__main__':
    main()

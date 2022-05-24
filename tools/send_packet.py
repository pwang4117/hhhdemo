#!/usr/bin/python

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

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python send_traffic.py packet_count src_ip")
        sys.exit(1)
    else:
        send_traffic(int(sys.argv[1]), src_ip=sys.argv[2])

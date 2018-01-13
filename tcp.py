#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import random
import pcap
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy


def get_tcp_mt(buff):
    """Pick out DHCP Message Type from buffer.
    """
    ether_packet = scapy.Ether(buff)
    tcp_packet = ether_packet[scapy.TCP]
    message = tcp_packet.sport
    print "message:", message


def setup_listener(iface, filter, timeout=2):
    listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
    listener.setfilter(filter)
    return listener


def send_tcp_over_qvb(iface, src_mac, srcip, src_port, dst_mac, dstip, dst_port):
    """Send DHCP Discovery over iface.
    """
    ethernet = scapy.Ether(dst=dst_mac,
                           src=src_mac, type=0x0800)
    ip = scapy.IP(src=srcip, dst=dstip)
    tcp = scapy.TCP(sport=int(src_port), dport=int(dst_port), seq=random.randrange(0,2**32), flags='S')
    packet = ethernet / ip / tcp
    scapy.sendp(packet, iface=iface)
    #scapy.sendp(packet, iface=iface, verbose=0)



if len(sys.argv) != 8:
    print "USAGE: %s <interface> <srcmac> <srcip> <dstmac> <dstip>" % sys.argv[0]
    exit(1)
else:
    iface = sys.argv[1]
    src_mac=sys.argv[2]
    srcip=sys.argv[3]
    src_port=sys.argv[4]
    dst_mac=sys.argv[5]
    dstip=sys.argv[6]
    dst_port=sys.argv[7]

# build filter
#filter = '(udp and (port 68 or 67) and ether host a0:36:9f:8f:bc:d3)'
filter = '(tcp and (port %s or %s))' % (src_port, dst_port)
print filter

# create listener on ethernet
listener = setup_listener(iface, filter)

# send packet
send_tcp_over_qvb(iface, src_mac, srcip, src_port,  dst_mac, dstip, dst_port)

# catch packet
packets = listener.readpkts()

for packet in packets:
    # analyes packet
    print '---'
    print get_tcp_mt(str(packet[1]))


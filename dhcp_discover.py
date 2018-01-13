#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import pcap
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy

scapy.conf.verb = 0

DHCP_MESSATE_TYPE = ['', 'DHCPDISCOVER', 'DHCPOFFER', 'DHCPREQUEST',
                     'DHCPDECLINE', 'DHCPACK', 'DHCPNAK', 'DHCPRELEASE']

def get_dhcp_mt(buff):
    """Pick out DHCP Message Type from buffer.
    """
    ether_packet = scapy.Ether(buff)
    dhcp_packet = ether_packet[scapy.DHCP]
    message = dhcp_packet.options[0]
    return DHCP_MESSATE_TYPE[message[1]]


def setup_listener(iface, filter, timeout=2):
    listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
    listener.setfilter(filter)
    return listener


def send_dhcp_over_qvb(iface, src_mac,srcip, dst_mac, dstip):
    """Send DHCP Discovery over iface.
    """
    ethernet = scapy.Ether(dst=dst_mac,
                           src=src_mac, type=0x0800)
    ip = scapy.IP(src=srcip, dst=dstip)
    udp = scapy.UDP(sport=68, dport=67)
    port_mac_t = tuple(map(lambda x: int(x, 16), src_mac.split(':')))
    hw = struct.pack('6B', *port_mac_t)
    bootp = scapy.BOOTP(chaddr=hw, flags=1)

    req = ''
    for i in xrange(1,255):
        req += chr(i)
    dhcp = scapy.DHCP(options=[("message-type", "discover"),('param_req_list',req), "end"])
    packet = ethernet / ip / udp / bootp / dhcp
    scapy.sendp(packet, iface=iface)
    #scapy.sendp(packet, iface=iface, verbose=0)


# build filter
#filter = '(udp and (port 68 or 67) and ether host a0:36:9f:8f:bc:d3)'
filter = '(udp and (port 68 or 67))'

if len(sys.argv) != 6:
    print "USAGE: %s <interface> <srcmac> <srcip> <dstmac> <dstip>" % sys.argv[0]
    exit(1)
else:
    iface = sys.argv[1]
    src_mac=sys.argv[2]
    srcip=sys.argv[3]
    dst_mac=sys.argv[4]
    dstip=sys.argv[5]

# create listener on ethernet
listener = setup_listener(iface, filter)

# send packet
send_dhcp_over_qvb(iface, src_mac, srcip, dst_mac, dstip)

# catch packet
packets = listener.readpkts()

for packet in packets:
    # analyes packet
    print '---'
    print get_dhcp_mt(str(packet[1]))


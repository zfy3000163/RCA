#!/usr/bin/env python
# _*_ coding=utf-8 _*_

import pcap
import sys,getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy

def main(iface, src_mac, src_ip, dst_ip):
    ethernet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=src_mac, type=0x0806)
    arp = scapy.ARP(
        op="who-has",

        hwsrc=src_mac,
        psrc=src_ip,

        hwdst="FF:FF:FF:FF:FF:FF",
        pdst=dst_ip

    )
    print((ethernet/arp).show())
    scapy.sendp(ethernet/arp, iface=iface)
    #sendp(eth/arp, inter=2, loop=1)

def get_arp_mt(buff):
    """Pick out DHCP Message Type from buffer.
    """
    ether_packet = scapy.Ether(buff)
    arp_packet = ether_packet[scapy.ARP]
    print(arp_packet).show()


def setup_listener(iface, filter, timeout=2):
    listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
    listener.setfilter(filter)
    return listener




if __name__ == "__main__":
    if len(sys.argv) != 5:
        print "USAGE: %s <interface> <srcmac> <srcip> <dstip>" % sys.argv[0]
        exit(1)
    else:
	iface=sys.argv[1]
        src_mac=sys.argv[2]
        src_ip=sys.argv[3]
        dst_ip=sys.argv[4]

    main(iface, src_mac, src_ip, dst_ip)


    filter = '(arp)'
    # create listener on ethernet
    listener = setup_listener(iface, filter)

    # catch packet
    packets = listener.readpkts()

    for packet in packets:
        # analyes packet
        print '---'
        print get_arp_mt(str(packet[1]))



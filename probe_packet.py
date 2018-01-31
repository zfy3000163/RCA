#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import pcap
import random
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy

scapy.conf.verb = 0


class DhcpProbe():
    def __init__(self):
        scapy.conf.verb = 0
        pass

    def get_mt(self, buff):
        """Pick out DHCP Message Type from buffer.
        """
        DHCP_MESSATE_TYPE = ['', 'DHCPDISCOVER', 'DHCPOFFER', 'DHCPREQUEST',
                     'DHCPDECLINE', 'DHCPACK', 'DHCPNAK', 'DHCPRELEASE']
        ether_packet = scapy.Ether(buff)
        udp_packet = ether_packet[scapy.UDP]
        #dhcp_packet = ether_packet[scapy.DHCP]
        #message = dhcp_packet.options[0]
        #return DHCP_MESSATE_TYPE[message[1]]
        return udp_packet.sport


    def setup_listener(self, iface, filter, timeout=2):
        listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
        listener.setfilter(filter)
        return listener


    def send_packet(self, iface, src_mac,src_ip, src_port, dst_mac, dst_ip, dst_port):
        ethernet = scapy.Ether(dst=dst_mac,
                               src=src_mac, type=0x0800)
        ip = scapy.IP(src=src_ip, dst=dst_ip)
        udp = scapy.UDP(sport=int(src_port), dport=int(dst_port))
        port_mac_t = tuple(map(lambda x: int(x, 16), src_mac.split(':')))
        hw = struct.pack('6B', *port_mac_t)
        bootp = scapy.BOOTP(chaddr=hw, flags=1)

        req = ''
        for i in xrange(1,255):
            req += chr(i)
        dhcp = scapy.DHCP(options=[("message-type", "discover"),('param_req_list',req), "end"])
        packet = ethernet / ip / udp / bootp / dhcp
        scapy.sendp(packet, iface=iface, verbose=0)


class TcpProbe():
    def __init__(self):
        scapy.conf.verb = 0
        pass

    def get_mt(self, buff):
        """Pick out TCP Message Type from buffer.
        """
        ether_packet = scapy.Ether(buff)
        tcp_packet = ether_packet[scapy.TCP]
        return tcp_packet.sport


    def setup_listener(self, iface, filter, timeout=2):
        listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
        listener.setfilter(filter)
        return listener


    def send_packet(self, iface, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port):
        ethernet = scapy.Ether(dst=dst_mac,
                               src=src_mac, type=0x0800)
        ip = scapy.IP(src=src_ip, dst=dst_ip)
        tcp = scapy.TCP(sport=int(src_port), dport=int(dst_port), seq=random.randrange(0,2**32), flags='S')
        packet = ethernet / ip / tcp
        scapy.sendp(packet, iface=iface)

class UdpProbe():
    def __init__(self):
        scapy.conf.verb = 0
        pass

    def get_mt(self, buff):
        """Pick out TCP Message Type from buffer.
        """
        ether_packet = scapy.Ether(buff)
        udp_packet = ether_packet[scapy.UDP]
        return udp_packet.sport


    def setup_listener(self, iface, filter, timeout=2):
        listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
        listener.setfilter(filter)
        return listener


    def send_packet(self, iface, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port):
        ethernet = scapy.Ether(dst=dst_mac,
                               src=src_mac, type=0x0800)
        ip = scapy.IP(src=src_ip, dst=dst_ip)
        udp = scapy.UDP(sport=int(src_port), dport=int(dst_port))
        data = "Hello udp"
        packet = ethernet / ip / udp / data
        scapy.sendp(packet, iface=iface)

class IcmpProbe():
    def __init__(self):
        scapy.conf.verb = 0
        pass

    def send_packet(self, iface, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port):
        ethernet = scapy.Ether(dst=dst_mac,
                               src=src_mac, type=0x0800)
        ip = scapy.IP(src=src_ip, dst=dst_ip)
        icmp = scapy.ICMP(type='echo-request', seq=random.randrange(0,2**10), id=random.randrange(0,2**15))/"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"

        scapy.sendp(ethernet/ip/icmp, iface=iface)

    def get_mt(self, buff):
        ether_packet = scapy.Ether(buff)
        icmp_packet = ether_packet[scapy.ICMP]
        return (icmp_packet).type


    def setup_listener(self, iface, filter, timeout=2):
        listener = pcap.pcap(iface, timeout_ms=timeout * 1000)
        listener.setfilter(filter)
        return listener







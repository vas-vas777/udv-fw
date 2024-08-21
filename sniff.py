#!/usr/bin/python3
from netfilterqueue import NetfilterQueue
from scapy.all import *
def print_and_accept(pkt):
    packet = IP(pkt.get_payload())
    if packet.haslayer(DNS) == True:
        if packet.getlayer(UDP).qd.qname == b'ya.ru.':
            send(IP(src="192.168.13.3", dst="192.168.13.2")/ICMP()/"DROP")
            pkt.drop()
        else:
            send(IP(src="192.168.13.3", dst="192.168.13.2")/ICMP()/"ACCEPT")
            pkt.drop()
    elif packet.haslayer(ICMP) == True:
        send(IP(src="192.168.13.3", dst="192.168.13.2")/ICMP()/"DROP")
        pkt.drop()
    else:
        send(IP(src="192.168.13.3", dst="192.168.13.2")/ICMP()/"ACCEPT")
        pkt.drop()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()

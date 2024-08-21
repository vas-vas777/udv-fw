#!/usr/bin/python3
from netfilterqueue import NetfilterQueue
from scapy.all import *

pkt_list=[]
def print_and_accept(pkt):
    scapy_pkt=IP(pkt.get_payload())
    if scapy_pkt.src != "192.168.13.3" and scapy_pkt.dst != "192.168.13.2":
        pkt_list.append(pkt)
        return

    if scapy_pkt.haslayer(ICMP) == True and scapy_pkt.src=="192.168.13.3" and scapy_pkt.dst=="192.168.13.2":
        if scapy_pkt.getlayer(ICMP).load == b'DROP':
            pkt.drop()
            for i in range (len(pkt_list)):
                pkt_list[i].drop()
            pkt_list.clear()
            return
        if scapy_pkt.getlayer(ICMP).load == b'ACCEPT':
            pkt.accept()
            for i in range(len(pkt_list)):
                pkt_list[i].accept()
            pkt_list.clear()
            return

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
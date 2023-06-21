import argparse
import sys
import socket
import random
import struct
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField,  ShortField, ByteField, LongField
from scapy.all import *
import numpy as np

TYPE_MESS = 0x1212
TYPE_IPV4 = 0x0800
sharedMem = np.chararray(10000)

def get_if(host_iface):
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if host_iface in i:
            iface=i
            break;
    if not iface:
        print("Cannot find " + host_iface + " interface")
        exit(1)
    return iface

class Mess(Packet):
    name: "Mess"
    fields_desc = [
        ShortField("prot", 0),
        ByteField("ms", 0),
        LongField("id",0),
        #ShortField("bId",0),
        IntField("start", 0),
        IntField("end",0)
    ]

def handle_pkt(pkt):
    print("Packet")
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    pkt.show2()
    sys.stdout.flush()

def main():
    if len(sys.argv) < 2:
        print('pass arguments: <interface>')
        exit(1)
    iface = get_if(sys.argv[1])
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    print("sniffing on %s" % iface)
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

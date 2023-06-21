import argparse
import binascii
import sys
import socket
import random
import struct
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField,  ShortField, ByteField, LongField
from scapy.all import *
from datetime import datetime
from threading import Thread
import numpy as np
sharedMem = np.chararray(1000)
TYPE_IPV4 = 0x0800
TYPE_MESS = 0x1212
lck = threading.Lock()
memLck = threading.Lock()
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
        # ShortField("bId",0),
        IntField("start", 0),
        IntField("end",0)
    ]

def handle_pkt(pkt, iface, _fil):
    f = open(_fil, 'a')
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    pkt.show2()
    sys.stdout.flush()
    now = datetime.now()
    dat = pkt[UDP].payload.load
    dat = dat.decode('ascii')
    ty = pkt[Mess].ms
    st = pkt[Mess].start
    end = pkt[Mess].end
    if(ty == 2):
        index = st
        for x in dat:
            memLck.acquire()
            sharedMem[index] = x
            memLck.release()
            index = index + 1
        finish = datetime.now()
        duration = finish - now
        comp_pkt = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src, type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 5, id = pkt[Mess].id, start = 0 , end = 0) / IP (dst = pkt[IP].src) / UDP(dport=4321, sport=1234) / Raw(format(f"{duration.microseconds}"))
        sendp(comp_pkt, iface=iface)
        lck.acquire()
        f.write(format(f'{pkt[Mess].id}, {duration.microseconds}\n'))
        f.flush()
        f.close()
        lck.release()
    elif(ty == 1):
        index = 0
        prev_star = 0
        star = 0
        sending = ""
        for x in range(st, end + 1):
            if(index == 1000):
                index = 0
                p = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src, type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 1, id = pkt[Mess].id, start = prev_star , end = star) / IP (dst = pkt[IP].src) / UDP(dport=4321, sport=1234) / Raw(sending) 
                sendp(p, iface)
                sending = ""
                prev_star = star
                continue
            memLck.acquire()
            if(index > 0 and index < 500):
                sending.append(sharedMem[x])
            memLck.release()
            index += 1
            star += 1
        if(sending != ""):
            p = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src, type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 1, id = pkt[Mess].id, start = prev_star , end = end) / IP (dst = pkt[IP].src) / UDP(dport=4321, sport=1234) / Raw(sending) 
            sendp(p, iface)
        finish = datetime.now()
        duration = finish - now
        comp_pkt = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src, type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 5, id = pkt[Mess].id, start = 0 , end = 0 ) / IP (dst = pkt[IP].src) / UDP(dport=4321, sport=1234) / Raw(format(f"{duration.microseconds}"))
        sendp(comp_pkt, iface=iface)
        lck.acquire()
        f.write(format(f'{pkt[Mess].id}, {duration.microseconds}\n'))
        f.flush()
        f.close()
        lck.release()
def receive(iface, _fil):
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    sniff(iface = iface, prn = lambda x: handle_pkt(x, iface, _fil))

def main():
    if len(sys.argv) < 3:
        print('pass arguments: <interface>')
        exit(1)
    iface = get_if(sys.argv[1])
    th = []
    print("sniffing on %s" % iface)
    for _ in sys.argv[3]:
        t = threading.Thread(target =receive, args=(iface, sys.argv[2]))
        t.start()
        th.append(t)
    # sniff(iface = iface, prn = lambda x: handle_pkt(x, iface, sys.argv[2]))
    for t in th:
        t.join()
if __name__ == '__main__':
    main()

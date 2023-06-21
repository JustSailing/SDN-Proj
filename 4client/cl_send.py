#!/usr/bin/env python 

import argparse
import sys
import socket
import random
import math
import struct
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField,  ShortField, ByteField, LongField
from scapy.all import *
from scapy.layers import *
from datetime import datetime
mp = dict()
lck = threading.Lock()
TYPE_IPV4 = 0x0800
TYPE_MESS = 0x1212
sentences = [None] * 10
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
        ShortField("prot",0),
        ByteField("ms", 0),
        LongField("id",0),
        # ShortField("bId",0),
        IntField("start", 0),
        IntField("end",0)
    ]
def gen_pkts(iface, addr, cl_num, ty):
    # in order for pkt.show to have the correct output
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    if(ty == "1"):
        for _ in range(100):
            for i, val in enumerate(sentences):
                v = 10
                if(cl_num == 2):
                    v = 20
                elif(cl_num == 3):
                    v = 30
                elif(cl_num == 4):
                    v = 40
                start = random.randrange(0,500)
                check = val + cl_num
                if((len(check) + start) < 500):
                    rd = random.randrange(0, sys.maxsize/2)
                    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff",type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 2, id = rd, start = start , end = start + len(val) ) / IP (dst = addr) / UDP(dport=4321, sport=1234) / Raw(format(f"{val}{cl_num} "))
                            
                    mp.update({rd: datetime.now()})             
                    sendp(pkt, iface=iface)
                    #pkt.show2()
                    #sys.stdout.flush()
                else:
                    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff",type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 2, id = rd, start = start , end = 500 ) / IP (dst = addr) / UDP(dport=4321, sport=1234) / Raw(format(f"{val[0:(500 - start -1)]} {cl_num} "))
                    rd = random.randrange(0, sys.maxsize/2)
                    #pkt.show2()
                    #sys.stdout.flush()
                    mp.update({rd: datetime.now()})
                    sendp(pkt, iface=iface)
    else:
        for i in range(100):
            for i in range(10):
                start = random.randrange(0,500)
                ed = random.randrange(start, 500)
                rd = random.randrange(0, sys.maxsize/2)
                pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff",type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, ms = 2, id =rd, start = start , end = ed ) / IP (dst = addr) / UDP(dport=4321, sport=1234) / Raw("x")
                sendp(pkt, iface=iface)
                mp.update({rd: datetime.now()})
                #pkt.show2()
                #sys.stdout.flush()

 
def handle_pkt(pkt, _fil):
    f = open(_fil, 'a')
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    dat = pkt[UDP].payload.load
    dat = dat.decode('ascii')
    if(pkt[Mess].ms == 5):
        fin = datetime.now()
        bef = mp[pkt[Mess].id]
        dur = fin - bef
        lck.acquire()
        f.write(format(f'{pkt[Mess].id}, {dur.microseconds}\n'))
        f.flush()
        f.close()
        lck.release()

def receive(iface, _fil):
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    sniff(iface = iface, prn = lambda x: handle_pkt(x, _fil))

def main():
    sentences[0] = " Hello cs550 from "
    sentences[1] = " P4 is weird but cool "
    sentences[2] = " Hopefully this works "
    sentences[3] = " Distributed Systems is awesome "
    sentences[4] = " I have no special talent. I am only passionately curious "
    sentences[5] = " You have to fight through some bad days to earn the best days of your life "
    sentences[6] = " Don't be afraid to give up the good to go for the great "
    sentences[7] = " A certain darkness is needed to see the stars "
    sentences[8] = " When something is important enough, you do it even if the odds are not in your favor "
    sentences[9] = " Doing your best is more important than being the best "

    iface = get_if(sys.argv[1])
    addr = socket.gethostbyname(sys.argv[2])
    qrec = threading.Thread(target=receive, args=(iface,sys.argv[5]))
    qrec.start()
    print(type(sys.argv[4]))
    print(sys.argv[4])
    gen_pkts(iface, addr, sys.argv[3], sys.argv[4])
    qrec.join()
    

if __name__ == '__main__':
    main()


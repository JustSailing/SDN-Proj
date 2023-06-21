#!/usr/bin/env python

from text import Text
import time
import heapq
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField,  ShortField, ByteField
from scapy.all import *
import curses
from curses import wrapper
from uuid import uuid4
# msg_id
UPDATE = 0
READ = 1
WRITE = 2
COMPLETED = 3
ERROR = 4
UPDATE_MULT = 5

# For type (ADD or DELETE) after matching WRITE msg_id
ADD = 1
DELETE = 2
# difference between ADD and ADD_NODE (ADD adds txt to already known node)
ADD_NODE = 3

# pointers to beginning of txt and end of txt
beg_txt = Text()
#beg_txt.end_idx = 50
#beg_txt.txt_blk_idx = 0
# end_txt = None

# used as ether type and ipv4 type
TYPE_MESS = 0x1212
TYPE_IPV4 = 0x0800

# lock and map for uuid to node pointer
map_lock = threading.Lock()
map_text_node = dict()  # uuid to Text node

# file for logging
log_lock = threading.Lock()
log_file = sys.argv[3]

# write to terminal lock
term_lock = threading.Lock()
# heap holding pkts. priority depending on the pkt[Mess].time
heap_lock = threading.Lock()
heap = []


class Mess(Packet):
    name: "Mess"
    fields_desc = [
        ShortField("prot", 0),
        ByteField("msg_id", 0),
        ByteField("type", 0),
        UUIDField("uuid", 0),
        IntField("txt_blk_idx", 0),
        IntField("len_txt", 0),
        IEEEFloatField("time", 0),
        IntField("start_idx", 0),
        IntField("end_idx", 0),
        # this should be the uuid of the previous node to the added node
        UUIDField("node_prev", 0),
        UUIDField("node_next", 0)
    ]
# the Text class field txt would be the payload of the packet


def get_if(host_iface):
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if host_iface in i:
            iface = i
            break
    if not iface:
        print("Cannot find " + host_iface + " interface")
        exit(1)
    return iface


def handle_add(pkt):
    global beg_txt
    if (pkt[Mess].msg_id == WRITE):
        if (pkt[Mess].type == ADD):
            map_lock.acquire()
            node = map_text_node.get(pkt[Mess].uuid, None)
            map_lock.release()
            if (node == None):
                temp = pkt[Ether].src
                pkt[Ether].src = pkt[Ether].dst
                pkt[Ether].dst = temp
                pkt[IP].dst = pkt[IP].src
                pkt[Mess].msg_id = ERROR
                pkt[Mess].time = time.time()
                pkt[UDP].payload.load = b""
                # ERROR only sent to the sender of the packet not to the rest of the connected writers or readers
                sendp(pkt)
                to_log = f"[ERROR] Adding to existing text block that does not exist [UUID] {pkt[Mess].uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()
            else:
                node.lock.acquire()
                s_idx = pkt[Mess].start_idx - node.start_idx
                # e_idx = pkt[Mess].end_idx - node.start_idx
                temp = node.text[s_idx:]
                node.txt[s_idx:pkt[Mess].len_txt] = bytearray(pkt[UDP].payload.load.decode(
                    'ascii'), 'ascii')
                node.txt[s_idx + pkt[Mess].len_txt:] = temp
                node.len_txt = len(node.txt)
                node.lock.release()
                to_log = f"[Success] Adding text to existing block [UUID] {pkt[Mess].uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()
        if (pkt[Mess].type == ADD_NODE):
            map_lock.acquire()
            node = map_text_node.get(pkt[Mess].node_prev, None)
            map_lock.release() 
            if (node == None):
                # beg_txt.lock.release()
                # ERROR only sent to the sender of the packet
                to_log = f"[ERROR] Adding new text block. Previous Node uuid does not exist [UUID] {pkt[Mess].uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()
            else:
                # needed since it would break the linked list. No way of connecting to end of the list
                temp = node.node_next
                new_node = Text()
                new_node.start_idx = pkt[Mess].start_idx
                new_node.end_idx = pkt[Mess].end_idx
                new_node.uuid = pkt[Mess].uuid
                new_node.txt = bytearray(
                    pkt[UDP].payload.load.decode('ascii'), 'ascii')
                new_node.len_txt = pkt[Mess].len_txt
                new_node.max = 50
               #new_node.cap = pkt[Mess].cap
                new_node.time = pkt[Mess].time
                node.lock.acquire()
                node.node_next = new_node
                node.lock.release()
                new_node.node_next = temp
                temp.lock.acquire()
                temp.node_prev = new_node
                temp.lock.release()
                map_lock.acquire()
                map_text_node[new_node.uuid] = new_node
                map_lock.release()
                to_log = f"[SUCCESS] Adding new text block [UUID] {new_node.uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()


def handle_delete(pkt):
    global beg_txt
    node = map_text_node.get(pkt[Mess].uuid, None)
    if (node == None):
        temp = pkt[Ether].src
        pkt[Ether].src = pkt[Ether].dst
        pkt[Ether].dst = temp
        pkt[IP].dst = pkt[IP].src
        pkt[Mess].msg_id = ERROR
        pkt[Mess].time = time.time()
        pkt[UDP].payload.load = b""
        # Multicast not needed. Just the sender of the change needs to know an error occurred
        # sendp(pkt)
        to_log = f"[ERROR] deletion in text block that does not exist [UUID] {pkt[Mess].uuid} [IP] {temp} [TIME] {datetime.now()}\n"
        w = open(log_file, "a")
        log_lock.acquire()
        w.write(to_log)
        log_lock.release()
        w.close()
    else:
        # assert pkt[Mess].start_idx < pkt[Mess].end_idx
        # ld = bytearray(pkt[Raw].load) # delete shouldn't have a payload
        node.lock.acquire()
        len_org = node.len_txt - 1
        s_idx = pkt[Mess].start_idx - node.start_idx  # start index for txt
        e_idx = pkt[Mess].end_idx - node.start_idx
        node.txt[s_idx:node.max] = node.text[e_idx:node.max]
        # make sure that the rest are '\0'
        num_del = len_org - (e_idx - s_idx)
        node.txt[num_del:] = b'\0'
        node.len_txt = node.len_txt - (e_idx - s_idx)
        node.lock.release()
        to_log = f"[SUCCESS] deleted at [Start] {pkt[Mess].start_idx} [End] {pkt[Mess].end_idx} [IP] {pkt[IP].src} [Time] {datetime.now()} \n"
        w = open(log_file, "a")
        log_lock.acquire()
        w.write(to_log)
        log_lock.release()
        w.close()


def handle_update(pkt):
    global beg_txt
    if (beg_txt.txt_blk_idx == 1):
        beg_txt.lock.acquire()
        beg_txt.start_idx = pkt[Mess].start_idx
        beg_txt.end_idx = pkt[Mess].end_idx
        beg_txt.txt_blk_idx = pkt[Mess].txt_blk_idx
        beg_txt.txt = bytearray(pkt[UDP].payload.load.decode('ascii'), 'ascii')
        beg_txt.len_txt = pkt[Mess].len_txt
        beg_txt.max = 50
       #beg_txt.cap = pkt[Mess].cap
        beg_txt.uuid = pkt[Mess].uuid
        beg_txt.time = pkt[Mess].time
        beg_txt.lock.release()
        map_lock.acquire()
        map_text_node[beg_txt.uuid] = beg_txt
        map_lock.release()
    else:
        node = beg_txt
        # node.lock.acquire()
        while (node.txt_blk_idx < pkt[Mess].txt_blk_idx and node != None):
            # node.lock.release()
            node = node.node_next
        if (node.node_prev == None):
            temp = Text()
            temp.start_idx = pkt[Mess].start_idx
            temp.end_idx = pkt[Mess].end_idx
            temp.txt_blk_idx = pkt[Mess].txt_blk_idx
            temp.txt = bytearray(pkt[UDP].payload.load.decode('ascii'), 'ascii')
            temp.len_txt = pkt[Mess].len_txt
            temp.max = 50
           #temp.cap = pkt[Mess].cap
            temp.uuid = pkt[Mess].uuid
            temp.time = pkt[Mess].time
            node.lock.acquire()
            org_prev = node.node_prev  # should be None, which means the node is beg_txt
            node.node_prev = temp
            node.release()
            org_prev.lock.acquire()
            beg_txt.lock.acqurie()
            beg_txt = org_prev
            beg_txt.lock.release()
            org_prev.lock.release()
            beg_txt.lock.acqurie()
            beg_txt.next = node
            map_lock.acquire()
            map_text_node[temp.uuid] = temp
            map_lock.release()
        else:
            temp = Text()
            temp.start_idx = pkt[Mess].start_idx
            temp.end_idx = pkt[Mess].end_idx
            temp.txt_blk_idx = pkt[Mess].txt_blk_idx
            temp.txt = bytearray(pkt[UDP].payload.load.decode('ascii'), 'ascii')
            temp.len_txt = pkt[Mess].len_txt
            temp.max = 50
           #temp.cap = pkt[Mess].cap
            temp.uuid = pkt[Mess].uuid
            temp.time = pkt[Mess].time
            node.lock.acquire()
            org_prev = node.node_prev
            node.node_prev = temp
            node.release()
            temp.node_next = node
            temp.node_prev = org_prev
            org_prev.lock.acquire()
            org_prev.node_next = temp
            org_prev.lock.release()
            map_lock.acquire()
            map_text_node[temp.uuid] = temp
            map_lock.release()



def delete_ch(y, x, height, width, iface,addr):
    global beg_txt
    pos = y * width + x
    node = beg_txt
    while(True):
        if(node == None):
            break
        node.lock.acquire()
        if(pos >= node.start_idx and pos <= node.end_idx):
            s_idx = pos - node.start_idx 
            temp = node.txt[s_idx + 1:]
            node[s_idx - 1:] = temp
            node[node.len_txt - 2:] = b'\0'
            node.len_txt = len(node.txt)
            p = Ether(src=get_if_hwaddr(iface), type=TYPE_MESS) / Mess(prot=TYPE_MESS, msg_id=WRITE, type=DELETE,
                                                                                 uuid=node.uuid, time=time.time(), start_idx = pos, end_idx = pos, len_txt = node.len_txt, node_prev = node.node_prev, node_next = node.node_next) / IP(dst=addr) / UDP(dport=4321, sport=1234) 
            send(p)
            node.lock.release()
        node.lock.release()
        node = node.node_next
def add(ch, y, x, height, width, iface, addr):
    global beg_txt
    pos = y * width + x
    node = beg_txt
    while(True):
        if(node == None):
            break
        node.lock.acquire()
        if(pos >= node.start_idx and pos <= node.end_idx):
            s_idx = pos - node.start_idx 
            temp = node.txt[:s_idx + 1]
            temp.append(bytearray(ch))
            temp.append(node.txt[s_idx + 1:])
            node.txt = temp
            # node[node.len_txt - 2:] = b'\0'
            node.len_txt = len(node.txt)
            p = Ether(src=get_if_hwaddr(iface), type=TYPE_MESS) / Mess(prot=TYPE_MESS, msg_id=DELETE,
                                                                                 uuid=node.uuid, time=time.time(), start_idx = pos, end_idx = pos, len_txt = node.len_txt, node_prev = node.node_prev, node_next = node.node_next) / IP(dst=addr) / UDP(dport=4321, sport=1234) 
            sendp(p)
            node.lock.release()
            break
        node.lock.release()
        prev = node
        node = node.node_next
        if(node == None):
            new_node = Text()
            new_node.start_idx = prev.end_idx + 1
            new_node.end_idx = new_node.start_idx + 50
            new_node.len_txt = 1
            new_node.txt = bytearray(chr(ch), 'ascii')
            new_node.uuid = uuid4()
            new_node.node_prev = prev
            new_node.time = time.time()
            prev.lock.acquire()
            prev.node_next = new_node
            p = Ether(src=get_if_hwaddr(iface), type=TYPE_MESS) / Mess(prot=TYPE_MESS, msg_id=WRITE, type= ADD_NODE,
                                                                                 uuid=new_node.uuid, time=new_node.time, start_idx = pos, end_idx = pos, len_txt = node.len_txt, node_prev = new_node.node_prev, node_next = None) / IP(dst=addr) / UDP(dport=4321, sport=1234) /Raw(new_node.txt)

            sendp(p)
            break

def handle():
    while(True):
        heap_lock.acquire()
        if(len(heap)== 0):
            heap_lock.release()
            continue
        pkt = heapq.heappop(heap)
        pkt = pkt[1]
        heap_lock.release()
        if (pkt[Mess].msg_id == UPDATE or pkt[Mess].msg_id == READ):
            handle_update(pkt)
        elif (pkt[Mess].msg_id == WRITE):
            if (pkt[Mess].type == ADD):
                handle_add(pkt)
            elif (pkt[Mess].type == DELETE):
                handle_delete(pkt)
        elif(pkt[Mess].msg_id == UPDATE_MULT):
            if (pkt[Mess].type == ADD):
                handle_add(pkt)
            elif (pkt[Mess].type == DELETE):
                handle_delete(pkt)

def handle_pkt(pkt):
    heap_lock.acquire()
    heapq.heappush(heap, (pkt[Mess].time,pkt))
    heap_lock.release()

def receive(iface,):
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


def main(stdscr):
    global beg_txt
    beg_txt.start_idx = 0
    beg_txt.end_idx = 50
    beg_txt.txt_blk_idx = 1
    iface = get_if(sys.argv[1])
    addr = socket.gethostbyname(sys.argv[2])
    # gen_pkts(iface, addr, sys.argv[3], sys.argv[4])
    # win = curses.newwin(height, width, 0, 0)
    th = []
    # log_file = sys.argv[3]
    for _ in range(int(sys.argv[4])//2):
        t = threading.Thread(target=receive, args=(iface, ))
        t.start()
        th.append(t)
        
    pkt = Ether(src=get_if_hwaddr(iface), type=TYPE_MESS) /  Mess(prot=TYPE_IPV4, msg_id = UPDATE) / IP (dst = addr) / UDP(dport=4321, sport=1234) / Raw()
    sendp(pkt)
    for _ in range(int(sys.argv[4])//2):
        t = threading.Thread(target = handle, args=())
        t.start()
        th.append(t)
    height, width = stdscr.getmaxyx()
    term_lock.acquire()
    stdscr.nodelay(True)
    term_lock.release()
    x, y = 0, 0
    while(True):
        stdscr.clear()
            # continue
        win_node = beg_txt
        row = 0
        col = 0
        while (win_node != None):
            win_node.lock.acquire()
         # amount_left = width - col
            index = 0
            s = ""
            while (index < win_node.len_txt):
                if (col > width):
                    term_lock.acquire()
                    stdscr.addstr(row, 0, s)
                    row = row + 1
                    col = 0
                    term_lock.release()
                    s = ""
                s = s + win_node.txt[index].decode('ascii')
                index = index + 1
                col += 1
            win_node.lock.release()
            win_node = win_node.node_next
            index = 0
        term_lock.acquire()
        stdscr.refresh()
        try:
            term_lock.acquire()
            key = stdscr.getch()
            term_lock.release()
        except:
            key = None
            continue
        if key == curses.KEY_LEFT:
            if(x - 1 < 0):
                x = 0
                # continue
            else:
                x -= 1
                # continue
        elif key == curses.KEY_RIGHT:
            if(x + 1 > width):
                x = width
                # continue
            else:
                x += 1
                # continue
        elif key == curses.KEY_UP:
            if(y - 1 < 0):
                y = 0
                # continue
            else:
                y -= 1
                # continue
        elif key == curses.KEY_DOWN:
            if(y + 1 > height):
                y = height
                # continue
            else:
                y += 1
                # continue
        elif key == curses.KEY_BACKSPACE:
            delete_ch(y, x, height, width, iface, addr)
            # continue
        else:
            add(key, y, x, height, width, iface, addr)
        term_lock.realease()

    for t in th:
        t.join()


if __name__ == '__main__':
    wrapper(main)


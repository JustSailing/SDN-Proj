from text import Text
import time
import heapq
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.all import IntField,  ShortField, ByteField, UUIDField, IEEEFloatField
from scapy.all import *

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
beg_txt.txt_blk_idx = 1
beg_txt.end_idx = 50
beg_txt.start_idx = 0
# end_txt = None # I do not think this is needed

# used as ether type and ipv4 type
TYPE_MESS = 0x1212
TYPE_IPV4 = 0x0800

# lock and map for uuid to node pointer
map_lock = threading.Lock()
map_text_node = dict()  # uuid to Text node

# file for logging
log_lock = threading.Lock()
log_file = "log_file.txt"

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


'''
    ADDs text on shared memory
'''


def handle_add(pkt):
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
                pkt[Raw].load = b""
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
                node.txt[s_idx:pkt[Mess].len_txt] = bytearray(pkt[Raw].load.decode(
                    'ascii'), 'ascii')
                node.txt[s_idx + pkt[Mess].len_txt:] = temp
                node.len_txt = len(node.txt)
                pkt_copy = pkt
                temp = pkt[Ether].src
                pkt[Ether].src = pkt[Ether].dst
                pkt[Ether].dst = temp
                pkt[IP].dst = pkt[IP].src
                pkt[Mess].msg_id = ERROR
                pkt[Mess].time = time.time()
                pkt[Raw].load = b""
                sendp(pkt)
                pkt_copy[Raw].load = node.txt.decode('ascii')
                pkt_copy[Mess].uuid = node.uuid
                pkt_copy[Mess].msg_id = UPDATE_MULT
                sendp(pkt_copy)
                node.lock.release()
                to_log = f"[Success] Adding text to existing block [UUID] {pkt[Mess].uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()
        if (pkt[Mess].type == ADD_NODE):
            map_lock.acquire()
            node = map_text_node.get(pkt[Mess].uuid, None)
            map_lock.release()
            if (node == None):
                beg_txt.lock.release()
                temp = pkt[Ether].src
                pkt[Ether].src = pkt[Ether].dst
                pkt[Ether].dst = temp
                pkt[IP].dst = pkt[IP].src
                pkt[Mess].msg_id = ERROR
                pkt[Mess].time = time.time()
                pkt[Raw].load = b""
                # ERROR only sent to the sender of the packet
                sendp(pkt)
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
                    pkt[Raw].load.decode('ascii'), 'ascii')
                new_node.len_txt = pkt[Mess].len_txt
                new_node.max = 50
                new_node.cap = pkt[Mess].cap
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
                pkt[Mess].uuid = new_node.uuid
                pkt[Mess].msg_id = UPDATE_MULT
                sendp(pkt)
                to_log = f"[SUCCESS] Adding new text block [UUID] {new_node.uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
                w = open(log_file, "a")
                log_lock.acquire()
                w.write(to_log)
                log_lock.release()
                w.close()


'''
   Delete Operation from clients 
'''


def handle_delete(pkt):
    # DEBUG
    # assert pkt[Mess].msg_id == WRITE
    # assert pkt[Mess].type == DELETE
    node = map_text_node.get(pkt[Mess].uuid, None)
    if (node == None):
        temp = pkt[Ether].src
        pkt[Ether].src = pkt[Ether].dst
        pkt[Ether].dst = temp
        temp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = temp
        pkt[Mess].msg_id = ERROR
        pkt[Mess].time = time.time()
        pkt[Raw].load = b""
        # Multicast not needed. Just the sender of the change needs to know an error occurred
        sendp(pkt)
        to_log = f"[ERROR] deletion in text block that does not exist [UUID] {pkt[Mess].uuid} [IP] {pkt[IP].src} [TIME] {datetime.now()}\n"
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
        p = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type=TYPE_MESS) / Mess(prot=TYPE_IPV4, msg_id=COMPLETED,
                                                                                 uuid=pkt[Mess].uuid, time=time.time()) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(dport=4321, sport=1234) / Raw("Completed")
        sendp(p)
        # Multicast (technically its a broadcast) the change to all connected hosts
        # NOTE: in p4 file may allow the multicast to writers first then multicast to readers afterwards
        pkt[Mess].msg_id = UPDATE_MULT
        sendp(p)
        to_log = f"[SUCCESS] deleted at [Start] {pkt[Mess].start_idx} [End] {pkt[Mess].end_idx} [IP] {pkt[IP].src} [Time] {datetime.now()} \n"
        w = open(log_file, "a")
        log_lock.acquire()
        w.write(to_log)
        log_lock.release()
        w.close()


"""
    Every time frame (fixed on server), they should get an update every fixed duration
    to ensure that the shared memory is consistent
"""


def handle_update(pkt):
    node = beg_txt
    w = open(log_file, "a")
    # index = 1
    while (node != None):
        node.lock.acquire()
        p = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src, type=TYPE_MESS) / Mess(prot=TYPE_IPV4, msg_id=UPDATE, uuid=node.uuid,  len_txt=node.len_txt, txt_blk_idx=node.txt_blk_idx,
                                                                                 time=node.time, start_idx=node.start_idx, end_idx=node.end_idx, node_prev=node.node_prev, node_next=node.node_next) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(dport=4321, sport=1234) / Raw(node.txt.decode('ascii'))
        sendp(p)
        p.show2()
        node.lock.release()
        to_log = f"[SUCCESS] Update: beginning text and end text the same [Start] {node.start_idx} [End] {node.end_idx} [IP] {pkt[IP].src} [Time] {datetime.now()} \n"
        log_lock.acquire()
        w.write(to_log)
        log_lock.release()
        node = node.node_next
        # index = index + 1

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

def receive(iface):
    bind_layers(Ether, Mess, type=TYPE_MESS)
    bind_layers(Mess, IP, prot=TYPE_IPV4)
    sniff(iface = iface, prn = lambda x: handle_pkt(x))

def main():
    # print("helloworld")
    iface = get_if(sys.argv[1])
    th = []
    log_file = sys.argv[2]
    for _ in range(int(sys.argv[3])//2):
        t = threading.Thread(target=receive, args=(iface,))
        t.start()
        th.append(t)
    for _ in range(int(sys.argv[3])//2):
        t = threading.Thread(target=handle, args=())
        t.start()
        th.append(t)
    for t in th:
        t.join()

if __name__ == '__main__':
    main()


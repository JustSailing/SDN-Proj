import threading
class Text():
    def __init__(self):
        self.start_idx = 0
        self.end_idx = 0
        self.txt_blk_idx = 0 # used only in update msg_id 
        self.txt = bytearray(50)
        self.len_txt = 0
        self.max = 50
        self.cap = 50
        self.uuid = None
        self.time = None
        self.node_next = None
        self.node_prev = None
        self.lock = threading.Lock()


import json

def init_config(self):
    self.if_name = None  # 网卡的 id, 用于捕获数据包
    self.packet_items = [] # 捕获的数据包信息
    self.packets_dict = {} # 捕获的原始数据包
    self.start_time = None # 捕获第一个数据包的时间戳

    self.sniffing_flag = 0 # 是否正在捕获
    self.current_message = ""
    self.support_protocol_list = ['HTTP', 'TCP', 'UDP', 'IPV6', 'ARP']
    self.filters = [] # 过滤
    self.filters_info = ""

def save_config(self):
    config = {
        'if_name': self.if_name
    }
    with open(self.config_path, 'w') as f:
        json.dump(config, f)

def load_config(self):
    with open(self.config_path, 'r') as f:
        config = json.load(f)
    return config
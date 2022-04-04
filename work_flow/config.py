
import json

def init_config(self):
    self.if_name = None  # 网卡的 id, 用于捕获数据包
    self.packet_items = [] # 捕获的数据包信息
    self.packets = []
    self.start_time = None # 捕获第一个数据包的时间戳
    self.sniffThread = None
    self.current_message = ""
    self.support_protocol_list = ['HTTP', 'TCP', 'UDP', 'IPV6', 'ARP', 'ICMP']
    self.filter_info = ""
    self.filters = None # 过滤
    self.rowcount = 0
    self.current_tab = None

    self.proto2color = {
        'HTTP': (228, 255, 199, 255),
        'TCP': (231, 230, 255, 255),
        'UDP': (218, 238, 255, 255),
        'IPV6': (252, 224, 255, 255),
        'ARP': (250, 240, 215, 255),
        'ICMP': (252, 224, 255, 255)
    }
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
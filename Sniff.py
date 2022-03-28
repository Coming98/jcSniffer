from PyQt5.QtCore import QThread, pyqtSignal
import scapy
from scapy.all import *


class SniffThread(QThread):
    HandleSignal = pyqtSignal(scapy.layers.l2.Ether)

    def __init__(self, filter, if_name):
        super().__init__()
        self.filter = filter
        self.if_name = if_name

    def run(self):
        sniff(filter=self.filter, iface=self.if_name,
              prn=lambda packet: self.HandleSignal.emit(packet))
#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   main.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   
'''


from struct import pack
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow, QFileDialog
from view.Ui_MainWindow import Ui_MainWindow
from view import init_view
from work_flow import analysis_packet, handle_packet_items, show_networks
from work_flow import config, handle_filter
from Sniff import SniffThread
from scapy.all import PacketList, wrpcap
import re
import sys
import os


class JCSnifferWindow(Ui_MainWindow, QMainWindow):

    def __init__(self):
        super(JCSnifferWindow, self).__init__()
        self.setupUi(self)

        self.config_path = './config.json'

        # 初始化界面
        init_view.init_welcome(self)

        # 初始化配置参数
        config.init_config(self)

        # 欢迎界面 选择网卡
        show_networks.main(self)

    def start_sniff(self):
        self.sniffThread = SniffThread("", self.if_name)
        self.sniffThread.HandleSignal.connect(self.display)
        self.sniffThread.start()

        # ToolBar
        self.toolBar.actions()[0].setEnabled(False)
        self.toolBar.actions()[1].setEnabled(True)
        self.toolBar.actions()[2].setEnabled(False)
        self.toolBar.actions()[3].setEnabled(False)
        self.toolBar.actions()[4].setEnabled(False)

    def end_sniff(self):
        self.sniffThread.terminate()
        
        init_view.statusBar_update(self)
        # ToolBar
        self.toolBar.actions()[0].setEnabled(True)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(True)
        self.toolBar.actions()[3].setEnabled(True)
        self.toolBar.actions()[4].setEnabled(False)

    def display(self, packet):
        # col. No.
        packet_number = len(self.packet_items) + 1

        # col. Time
        packet_time = packet.time
        if(self.start_time is None):
            self.start_time = packet_time

        # col. Source, Destinaiton, Protocol, Length, Info
        packet_infos = analysis_packet.analysis_network(packet, brief=True)
        if(packet_infos == None): return

        packet_infos['No.'] = str(packet_number)
        packet_infos['Time'] = f'{packet_time - self.start_time:.6f}'
        # self.packets_dict[packet_infos['No.']] = packet
        self.packets.append(packet)

        self.packet_items.append(packet_infos)

        handle_packet_items.show_packet_items_table(self)

        # self.statusBar().showMessage(
        #     f"{self.if_name} | 捕获正在进行 ... | 已捕获: {len(self.packet_items)} · 已显示: {self.rowcount} | {self.filters_info}")
        init_view.statusBar_update(self)

    def quit(self):
        init_view.taggle_info_window(self, True)
        self.if_name == None
        self.packet_items = []
        self.packets = []
        # self.packets_dict = {}
        self.packet_items_table.setRowCount(0)
        init_view.statusBar_update(self)

        self.sniffThread = None
        self.rowcount = 0
        init_view.update_packet_detail_tabs(self)
        init_view.statusBar_update(self)

        # ToolBar
        self.toolBar.actions()[0].setEnabled(False)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(False)
        self.toolBar.actions()[3].setEnabled(False)
        self.toolBar.actions()[4].setEnabled(False)

    def save(self):
        path, filetype = QFileDialog.getSaveFileName(None,
                            "选择保存路径",
                            "./",
                            "pcap文件(*.cap);;全部(*)")
        if len(path.strip()) == 0 or not os.path.exists(os.path.dirname(path)): 
            QtWidgets.QMessageBox.critical(None, "错误", "路径不存在")
        else:
            packets = PacketList(self.packets)
            wrpcap(path, packets)
            QtWidgets.QMessageBox.information(None,"Success", "保存成功")

    def download(self):
        name, src, dst, number = self.download_name, self.download_src, self.download_dst, self.download_begin_number
        print(name, src, dst, number)

        if(not all([name, src, dst, number])): 
            print("Function exceed!")
            return
        
        packets = self.packets
        target_infos = (None, None, None)
        image_load = b""
        image_load_seq = []
        for i, packet in enumerate(packets[number-1:], number):
            if(not (packet.haslayer('IP') and packet['IP'].src == src and packet['IP'].dst == dst)): continue
            # print("GET Target", i)
            if packet.haslayer('Raw'):
                load = packet.load
                ack = packet.ack
                seq = packet.seq
                try:
                    if(b'200 OK' in load):
                        # print("GET Target 200 OK")
                        meta_type, length = re.search(r'Content-type: (.*?)\r\n.*?Content-Length: (.*?)\r\n', load.decode()).groups()
                        file_type = meta_type.split('/')[-1]
                        length = int(length)
                        if(target_infos[0] is None): target_infos = (ack, file_type, length)
                        elif(target_infos[0] == ack):
                            pass
                            # print("packet repeat")
                        else:
                            print("More resources!!!")
                            return
                    elif ack == target_infos[0] and seq not in image_load_seq:
                        image_load += load
                        image_load_seq.append(seq)
                        if(load.find(b'\xff\xd9') != -1):
                            break
                except:
                    print("Wrong Image")
                    return
        if(target_infos[0] is not None):
            # print("Success")
            path, filetype = QFileDialog.getSaveFileName(None,
                            "选择保存路径",
                            f"./{name}",
                            "jpeg文件(*.jpg);;全部(*)")
            if len(path.strip()) == 0 or not os.path.exists(os.path.dirname(path)): 
                QtWidgets.QMessageBox.critical(None, "错误", "路径不存在")
            else:
                with open(path, 'wb') as f:
                    f.write(image_load)
                QtWidgets.QMessageBox.information(None,"Success", "保存成功")
        else:
            QtWidgets.QMessageBox.critical(None, "错误", "保存失败，请等待功能更新，重试也没用哈~")
            return

    # Events

    def main_if_infos_table_doubleClicked(self, item):
        table = self.main_if_infos_table
        row = item.row()
        self.if_name = table.item(row, 1).text()

        # 进入捕获界面
        init_view.taggle_info_window(self, False)

        init_view.statusBar_update(self)

        # ToolBar
        self.toolBar.actions()[0].setEnabled(True)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(True)
        self.toolBar.actions()[2].setEnabled(False)

    def main_if_infos_table_clicked(self, item):
        table = self.main_if_infos_table
        row = item.row()
        self.if_name = table.item(row, 1).text()

        init_view.statusBar_update(self)

    def main_if_infos_table_itemSelectionChanged(self):
        if(not self.main_if_infos_table.currentItem().isSelected()):
            init_view.statusBar_update(self)

    def packet_detail_tab_tabBarClicked(self, index):
        # print(f'{index} / {self.packet_detail_tab.count()}')
        # print(self.packet_detail_tab.currentWidget())
        self.packet_detail_tab.setCurrentIndex(index)
        self.current_tab = self.packet_detail_tab.currentWidget()

    def packet_items_table_clicked(self, item):
        for _ in range(self.packet_detail_tab.count()):
            self.packet_detail_tab.removeTab(0)
        table = self.packet_items_table
        row = item.row()
        packet_number = table.item(row, 0).text()
        # packet = self.packets_dict[packet_number]
        packet = self.packets[int(packet_number)-1]
        handle_packet_items.show_packet_detail_tab(self, packet, packet_number)
        try:
            self.packet_detail_tab.setCurrentWidget(self.current_tab)
        except:
            self.packet_detail_tab.setCurrentWidget(self.tab_hexdata)
        
        source = table.item(row, 2).text()
        destination = table.item(row, 3).text()
        protocol = table.item(row, 4).text()
        info = table.item(row, 6).text()
        res = re.search(r'GET(.*?)jp[e]?g', info)
        if(protocol == 'HTTP' and res):
            self.download_name = res.group(1).split('/')[-1] + 'jpg'
            self.download_src = destination
            self.download_dst = source
            self.download_begin_number = int(packet_number) + 1
            self.toolBar.actions()[4].setEnabled(True)
        else:
            self.download_name = None
            self.download_src = None
            self.download_dst = None
            self.download_begin_number = None
            self.toolBar.actions()[4].setEnabled(False)


    def packet_filter_lineedit_returnPressed(self):
        lineedit = self.packet_filter_lineedit
        filter_info = lineedit.text().strip()
        if(len(filter_info) == 0): # 显示所有信息
            self.filter_info = ""
            self.filters = None
            handle_packet_items.show_packet_items_table_by_filter(self)
            init_view.statusBar_update(self)
            lineedit.setStyleSheet("QLineEdit { background-color: white }")
        else:
            flag = handle_filter.update_filter(self, filter_info)
            if(not flag[0]): # 错误过滤，不改变当前状态
                self.filter_info = flag[1]
                init_view.statusBar_update(self)
                lineedit.setStyleSheet("QLineEdit { background-color: #FFAFAF }")
            else:  # 正确过滤，改变显示
                self.filters = flag[1]
                self.filter_info = filter_info
                # 更新显示内容
                handle_packet_items.show_packet_items_table_by_filter(self)
                init_view.statusBar_update(self)
                lineedit.setStyleSheet("QLineEdit { background-color: #AFFFAF }")

if __name__ == "__main__":
    # QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    app = QtWidgets.QApplication(sys.argv)
    snifferWindow = JCSnifferWindow()
    snifferWindow.show()
    sys.exit(app.exec_())

#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   main.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   
'''


from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtCore import QThread, pyqtSignal
# from PyQt5.QtGui import QBrush, QColor
from view.Ui_MainWindow import Ui_MainWindow
from view.init_view import init_view_main
from work_flow import analysis_packet, handle_packet_items, show_networks

import scapy
from scapy.all import *
import sys


class SnifferWindow(Ui_MainWindow, QMainWindow):

    def __init__(self):
        super(SnifferWindow, self).__init__()
        self.setupUi(self)

        self.if_name = None  # 网卡的 id, 用于捕获数据包
        self.packet_items = [] # 捕获的数据包
        self.start_time = None # 捕获第一个数据包的时间戳
        self.status_message_pattern = '{if_name} | {status}'
        # 初始化界面
        init_view_main(self)

        # 欢迎界面 选择网卡
        show_networks.main(self)

    def main_if_infos_table_doubleClicked(self, item):
        # print(dir(item))
        # print(item.column())
        # print(item.data(0))
        # if_index = table.takeItem(row, 0)

        table = self.main_if_infos_table
        row = item.row()
        self.if_name = table.item(row, 1).text()

        # 进入捕获界面
        self.main_if_infos_table.hide()
        self.taggle_info_window(False)

        # 状态栏信息
        self.statusBar().showMessage(self.status_message_pattern.format(if_name=self.if_name, status='等待捕获开始...'))

    def taggle_info_window(self, visible):

        self.main_image_label.setVisible(visible)
        self.main_header_label.setVisible(visible)
        self.main_if_infos_table.setVisible(visible)
        self.main_footer_text.setVisible(visible)

        self.infos_table.setVisible(not visible)
        self.infos_detail_tab.setVisible(not visible)

    def start_sniff(self):
        self.statusBar().showMessage(self.status_message_pattern.format(if_name=self.if_name, status='捕获正在进行 ...'))
        # * 获取 filter 信息

        # *
        self.sniffThread = SniffThread("", self.if_name)
        self.sniffThread.HandleSignal.connect(self.display)
        self.sniffThread.start()

    def end_sniff(self):
        self.statusBar().showMessage(self.status_message_pattern.format(if_name=self.if_name, status='捕获停止'))

        self.sniffThread.terminate()

    def display(self, packet):

        # col. No.
        packet_number = len(self.packet_items) + 1

        # col. Time
        packet_time = packet.time
        if(self.start_time is None): self.start_time = packet_time

        # col. Source, Destinaiton, Protocol, Length, Info
        packet_infos = analysis_packet.main(packet)

        packet_infos['No.'] = str(packet_number)
        packet_infos['Time'] = f'{packet_time - self.start_time:.6f}'
        

        self.packet_items.append(packet_infos)

        handle_packet_items.show(self)


    # def main_if_infos_table_cellHover(self, row, _):
    #     table = self.main_if_infos_table
    #     column_count = table.columnCount()

    #     cur_row = row
    #     old_row = self.main_if_infos_table_cur_hover_row

    #     cur_items = [table.item(cur_row, idx) for idx in range(column_count)]
    #     old_items = [table.item(old_row, idx) for idx in range(column_count)]

    #     if cur_row != old_row:
    #         for item in old_items:
    #             item.setBackground(QBrush(QColor('white')))
    #         for item in cur_items:
    #             item.setBackground(QBrush(QColor('steelblue')))

    #     self.main_if_infos_table_cur_hover_row = cur_row


class SniffThread(QThread):
    HandleSignal = pyqtSignal(scapy.layers.l2.Ether)

    def __init__(self, filter, if_name):
        super().__init__()
        self.filter = filter
        self.if_name = if_name

    def run(self):
        sniff(filter=self.filter, iface=self.if_name,
              prn=lambda packet: self.HandleSignal.emit(packet))

    # def pack_callback(self,packet):
    #     packet.show()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    snifferWindow = SnifferWindow()
    snifferWindow.show()
    sys.exit(app.exec_())

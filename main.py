#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   main.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   
'''


from re import T
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtCore import QThread, pyqtSignal
# from PyQt5.QtGui import QBrush, QColor
from view.Ui_MainWindow import Ui_MainWindow
from view import init_view
from work_flow import analysis_packet, handle_packet_items, show_networks
from work_flow import config
from Sniff import SniffThread
import sys


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
        # 获取 filter 信息
        pass

        self.sniffThread = SniffThread("", self.if_name)
        self.sniffThread.HandleSignal.connect(self.display)
        self.sniffThread.start()

        self.statusBar().showMessage(f"{self.if_name} | 捕获正在进行 ...")

        # ToolBar
        self.toolBar.actions()[0].setEnabled(False)
        self.toolBar.actions()[1].setEnabled(True)
        self.toolBar.actions()[2].setEnabled(False)


    def end_sniff(self):
        self.sniffThread.terminate()
        self.statusBar().showMessage(f"{self.if_name} | 捕获停止")
        # ToolBar
        self.toolBar.actions()[0].setEnabled(True)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(True)

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

        self.statusBar().showMessage(f"{self.if_name} | 捕获正在进行 ... || 已捕获: {len(self.packet_items)} · 已显示: {self.packet_items_table.rowCount()}||")


    ################### Events

    def main_if_infos_table_doubleClicked(self, item):
        table = self.main_if_infos_table
        row = item.row()
        self.if_name = table.item(row, 1).text()

        # 进入捕获界面
        init_view.taggle_info_window(self, False)

        # 状态栏信息
        self.statusBar().showMessage(f"{self.if_name} | 等待捕获开始...")

        # ToolBar
        self.toolBar.actions()[0].setEnabled(True)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(True)

    def main_if_infos_table_clicked(self, item):
        table = self.main_if_infos_table
        row = item.row()
        self.if_name = table.item(row, 1).text()

        # 状态栏信息
        self.statusBar().showMessage(f"{self.if_name}")

    def main_if_infos_table_itemSelectionChanged(self):
        if(not self.main_if_infos_table.currentItem().isSelected()):
            self.statusBar().showMessage("")


    def quit(self):
        init_view.taggle_info_window(self, True)
        self.if_name == None
        self.statusBar().showMessage("")

        # ToolBar
        self.toolBar.actions()[0].setEnabled(False)
        self.toolBar.actions()[1].setEnabled(False)
        self.toolBar.actions()[2].setEnabled(False)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    snifferWindow = JCSnifferWindow()
    snifferWindow.show()
    sys.exit(app.exec_())

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
# from PyQt5.QtCore import *
from PyQt5.QtGui import QBrush, QColor
from view.Ui_MainWindow import Ui_MainWindow
from view.init_view import init_view_main
from work_flow import show_networks
import sys


class SnifferWindow(Ui_MainWindow, QMainWindow):
    
    def __init__(self):
        super(SnifferWindow, self).__init__()
        self.setupUi(self)

        # 初始化界面
        init_view_main(self)

        # 欢迎界面 选择网卡
        show_networks.main(self)

    def main_if_infos_table_cellHover(self, row, _):
        table = self.main_if_infos_table
        column_count = table.columnCount()

        cur_row = row
        old_row = self.main_if_infos_table_cur_hover_row

        cur_items = [table.item(cur_row, idx) for idx in range(column_count)]
        old_items = [table.item(old_row, idx) for idx in range(column_count)]


        if cur_row != old_row:
            for item in old_items:
                item.setBackground(QBrush(QColor('white')))
            for item in cur_items:
                item.setBackground(QBrush(QColor('steelblue')))                

        self.main_if_infos_table_cur_hover_row = cur_row

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    snifferWindow = SnifferWindow()
    snifferWindow.show()
    sys.exit(app.exec_())
#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   init_view.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   Initialization window interface processing
'''
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QAction, QHeaderView, QAbstractItemView, QFrame
import os

ICON_DIR = './resource/icon'


def init_view_main(window):

    # bgcolor
    window.setStyleSheet("#MainWindow{background-color: white}") 
    window.main_header_label.setAlignment(Qt.AlignCenter)
    window.main_footer_text.setStyleSheet("QTextBrowser{border-width:0;border-style:outset}") 


    # init size
    window.resize(1867, 1198)
    
    # init toolbar
    init_view_toolbar(window)

    # init main_if_infos_table
    init_main_if_infos_table(window, window.main_if_infos_table)

    # init infos_table
    init_infos_table(window)

def init_main_if_infos_table(window, table):
    table.setColumnHidden(0, True) # 隐藏 index 列
    table.verticalHeader().setVisible(False)  # 隐藏列名
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) # 自适应宽度
    table.horizontalHeader().setSectionsClickable(False) # 禁止点击表头
    table.setSelectionBehavior(QAbstractItemView.SelectRows) # 只能选择一行
    table.setEditTriggers(QAbstractItemView.NoEditTriggers) # 不可更改
    font = QFont('微软雅黑', 14)
    font.setBold(True)
    table.horizontalHeader().setFont(font)  # 设置表头字体
    table.horizontalHeader().setStyleSheet('QHeaderView::section{background:gray; color:white}')
    table.setAlternatingRowColors(True)
    table.setFrameStyle(QFrame.NoFrame)
    table.setStyleSheet('gridline-color:white;'
                'border:0px solid gray')
    # # Hover 一行的效果
    # table.setMouseTracking(True)
    # window.main_if_infos_table_cur_hover_row = 0
    # table.cellEntered.connect(window.main_if_infos_table_cellHover)

def init_view_toolbar(window):
    # 间距
    window.toolBar.setStyleSheet("QToolBar{spacing:16px;padding-left:12px;}")


    startAction = QAction(QIcon(os.path.join(ICON_DIR, 'start')),'Start (Ctrl+B)', window)
    startAction.setShortcut('Ctrl+B')
    startAction.triggered.connect(window.start_sniff)
    window.toolBar.addAction(startAction)

    endAction = QAction(QIcon(os.path.join(ICON_DIR, 'end')),'Stop (Ctrl+E)', window)
    endAction.setShortcut('Ctrl+E')
    endAction.triggered.connect(window.end_sniff)
    window.toolBar.addAction(endAction)

def init_infos_table(window):
    table = window.infos_table
    table.verticalHeader().setVisible(False)  # 隐藏列名
    table.horizontalHeader().setStretchLastSection(True) # 设置最后一列拉伸至最大
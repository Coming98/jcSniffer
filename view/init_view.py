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
from PyQt5.QtGui import QIcon, QFont, QPixmap
from PyQt5.QtWidgets import QAction, QHeaderView, QAbstractItemView, QFrame
import os
import sys
sys.path.append('../')

ICON_DIR = './resource/icon'
MAIN_IMAGE_PATH = './resource/images/main.png'


def taggle_info_window(window, visible):

    window.main_image_label.setVisible(visible)
    window.main_header_label.setVisible(visible)
    window.main_if_infos_table.setVisible(visible)
    window.main_footer_text.setVisible(visible)

    window.packet_items_table.setVisible(not visible)
    window.packet_detail_tab.setVisible(not visible)


################ ↓ Show ###########################

def init_packet_detail_treewidget(window):
    
    physical = window.packet_detail_physical_tree
    datalink = window.packet_detail_datalink_tree
    network = window.packet_detail_network_tree
    transport = window.packet_detail_transport_tree
    application = window.packet_detail_application_tree
    physical.setStyleSheet("QTreeWidget::item{margin: 6px; font-size: 16px}")
    datalink.setStyleSheet("QTreeWidget::item{margin: 6px; font-size: 16px}")
    network.setStyleSheet("QTreeWidget::item{margin: 6px; font-size: 16px}")
    transport.setStyleSheet("QTreeWidget::item{margin: 6px; font-size: 16px}")
    application.setStyleSheet("QTreeWidget::item{margin: 6px; font-size: 16px}")

def init_packet_detail_tabs(window):
    tab = window.packet_detail_tab
    tab.tabBarClicked.connect(window.packet_detail_tab_tabBarClicked)

def update_packet_detail_tabs(window):
    window.packet_detail_hexdata_text.clear()
    window.packet_detail_physical_tree.clear()
    window.packet_detail_datalink_tree.clear()
    window.packet_detail_network_tree.clear()
    window.packet_detail_transport_tree.clear()
    window.packet_detail_application_tree.clear()
    window.packet_detail_physical_tree.headerItem().setText(0, "")
    window.packet_detail_datalink_tree.headerItem().setText(0, "")
    window.packet_detail_network_tree.headerItem().setText(0, "")
    window.packet_detail_transport_tree.headerItem().setText(0, "")
    window.packet_detail_application_tree.headerItem().setText(0, "")
    for _ in range(window.packet_detail_tab.count()):
        window.packet_detail_tab.removeTab(0)
    
    tab_list = [window.tab_hexdata, window.tab_physical, window.tab_datalink, window.tab_network, window.tab_transport, window.tab_application]
    tab_name = ['Hex Data', 'Physical', 'DataLink', 'Network', 'Transport', 'Application']
    
    [ window.packet_detail_tab.insertTab(0, tab_list[i], tab_name[i] ) for i in range(len(tab_list))]

# packet_items_table
def init_packet_items_table(window):
    table = window.packet_items_table
    table.verticalHeader().setVisible(False)  # 隐藏列名
    table.horizontalHeader().setStretchLastSection(True)  # 设置最后一列拉伸至最大
    table.horizontalHeader().setSectionsClickable(False)  # 禁止点击表头
    table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 只能选择一行
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 不可更改
    font = QFont('微软雅黑', 14)
    font.setBold(True)
    table.horizontalHeader().setFont(font)  # 设置表头字体
    table.horizontalHeader().setStyleSheet(
        'QHeaderView::section{background:gray; color:white}')
    table.setAlternatingRowColors(True)
    table.setFrameStyle(QFrame.NoFrame)
    table.setStyleSheet('gridline-color:white;'
                        'border:0px solid gray')
    table.itemClicked.connect(window.packet_items_table_clicked)

def init_packet_filter_lineedit(window):
    window.packet_filter_lineedit.returnPressed.connect(window.packet_filter_lineedit_returnPressed)

################ ↑ Show ###########################


################ ↓ Welcome ###########################

# main_if_infos_table
def init_welcome_main_if_infos_table(window):
    table = window.main_if_infos_table
    table.setColumnHidden(0, True)  # 隐藏 index 列
    table.verticalHeader().setVisible(False)  # 隐藏列名
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 自适应宽度
    table.horizontalHeader().setSectionsClickable(False)  # 禁止点击表头
    table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 只能选择一行
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 不可更改
    font = QFont('微软雅黑', 14)
    font.setBold(True)
    table.horizontalHeader().setFont(font)  # 设置表头字体
    table.horizontalHeader().setStyleSheet(
        'QHeaderView::section{background:gray; color:white}')
    table.setAlternatingRowColors(True)
    table.setFrameStyle(QFrame.NoFrame)
    table.setStyleSheet('gridline-color:white;'
                        'border:0px solid gray')
    table.itemClicked.connect(window.main_if_infos_table_clicked)
    table.itemSelectionChanged.connect(window.main_if_infos_table_itemSelectionChanged)
# main_image_label
def init_welcome_main_image_label(window):
    main_image_obj = QPixmap(MAIN_IMAGE_PATH)
    window.main_image_label.setPixmap(main_image_obj)
    window.main_image_label.setScaledContents(True)  # 让图片自适应label大小

# ToolBar
def init_welcome_toolbar(window):

    window.toolBar.setStyleSheet(
        "QToolBar{spacing:16px;padding-left:12px;}")  # 间距

    # 开始按钮
    startAction = QAction(
        QIcon(os.path.join(ICON_DIR, 'start')), 'Start (Ctrl+B)', window)
    startAction.setShortcut('Ctrl+B')
    startAction.triggered.connect(window.start_sniff)
    window.toolBar.addAction(startAction)
    startAction.setDisabled(True)

    # 结束按钮
    endAction = QAction(QIcon(os.path.join(ICON_DIR, 'end')),
                        'Stop (Ctrl+E)', window)
    endAction.setShortcut('Ctrl+E')
    endAction.triggered.connect(window.end_sniff)
    window.toolBar.addAction(endAction)
    endAction.setDisabled(True)


    # 退出按钮
    quitAction = QAction(QIcon(os.path.join(ICON_DIR, 'quit')),
                        'Quit (Ctrl+Q)', window)
    quitAction.setShortcut('Ctrl+Q')
    quitAction.triggered.connect(window.quit)
    window.toolBar.addAction(quitAction)
    quitAction.setDisabled(True)

    # print(dir(window.toolBar))

# MainWindow
def init_welcome_mainwindow(window):
    window.setStyleSheet("#MainWindow{background-color: white}")  # 背景色
    window.main_header_label.setAlignment(Qt.AlignCenter)  # 欢迎内容剧中
    window.main_footer_text.setStyleSheet(
        "QTextBrowser{border-width:0;border-style:outset}")  # 页脚文字去除边框
    window.resize(1867, 1198)  # resize


def init_welcome(window):

    # MainWindow
    init_welcome_mainwindow(window)

    # ToolBar
    init_welcome_toolbar(window)

    # main_image_label
    init_welcome_main_image_label(window)

    # main_if_infos_table
    init_welcome_main_if_infos_table(window)

    # packet_items_table
    init_packet_items_table(window)

    # packet_filter_lineedit
    init_packet_filter_lineedit(window)

    # packet_detail_treewidget
    init_packet_detail_treewidget(window)
    
    # taggle_info_window
    taggle_info_window(window, True)

    # packet_detail_tabs
    init_packet_detail_tabs(window)

    update_packet_detail_tabs(window)


################ ↑ Welcome ###########################

def statusBar_update(window):
    if_name, sniff_status, count_info, filter_info = [None, ] * 4

    if(window.if_name is not None):
        if_name = window.if_name
    
    if(window.sniffThread is not None):
        sniff_status = "捕获正在进行..." if window.sniffThread.isRunning() else "捕获停止"
    
    if(len(window.packet_items) != 0):
        count_info = f"已捕获: {len(window.packet_items)} · 已显示: {window.rowcount} ({window.rowcount/len(window.packet_items):.2%})"
    if(window.filter_info != ""):
        filter_info = window.filter_info

    infos = [item for item in (if_name, sniff_status, count_info, filter_info) if item is not None]

    if(len(infos)):
        infos = ' | '.join(infos)
    else:
        infos = ''
    
    window.statusBar().showMessage(infos)
        

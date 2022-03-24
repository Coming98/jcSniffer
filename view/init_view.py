#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   init_view.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   Initialization window interface processing
'''
from PyQt5.QtCore import *
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QAction
import os

ICON_DIR = './resource/icon'


def init_view_main(window):
    # init size
    window.resize(1867, 1198)
    
    # init toolbar
    init_view_toolbar(window)

def init_view_toolbar(window):
    # 间距
    window.toolBar.setStyleSheet("QToolBar{spacing:16px;padding-left:12px;}")


    startAction = QAction(QIcon(os.path.join(ICON_DIR, 'start')),'Start (Ctrl+B)', window)
    startAction.setShortcut('Ctrl+B')
    startAction.triggered.connect(lambda : print('Toolbar-Start Success!'))
    window.toolBar.addAction(startAction)

    startAction = QAction(QIcon(os.path.join(ICON_DIR, 'end')),'Stop (Ctrl+E)', window)
    startAction.setShortcut('Ctrl+B')
    startAction.triggered.connect(lambda : print('Toolbar-End Success!'))
    window.toolBar.addAction(startAction)
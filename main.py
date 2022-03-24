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
from view.Ui_MainWindow import Ui_MainWindow
from view.init_view import init_view_main
import sys


class SnifferWindow(Ui_MainWindow, QMainWindow):
    
    def __init__(self):
        super(SnifferWindow, self).__init__()
        self.setupUi(self)
        init_view_main(self)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    snifferWindow = SnifferWindow()
    snifferWindow.show()
    sys.exit(app.exec_())
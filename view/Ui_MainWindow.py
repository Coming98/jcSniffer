# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'd:\workspace\01Github\03myWheel\jcSniffer\view\MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(753, 642)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem, 3, 0, 1, 1)
        self.infos_table = QtWidgets.QTableWidget(self.centralwidget)
        self.infos_table.setEnabled(True)
        self.infos_table.setAutoFillBackground(False)
        self.infos_table.setLineWidth(1)
        self.infos_table.setObjectName("infos_table")
        self.infos_table.setColumnCount(7)
        self.infos_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.infos_table.setHorizontalHeaderItem(6, item)
        self.gridLayout.addWidget(self.infos_table, 6, 0, 1, 2)
        self.main_header_label = QtWidgets.QLabel(self.centralwidget)
        self.main_header_label.setEnabled(False)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.main_header_label.sizePolicy().hasHeightForWidth())
        self.main_header_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.main_header_label.setFont(font)
        self.main_header_label.setObjectName("main_header_label")
        self.gridLayout.addWidget(self.main_header_label, 2, 0, 1, 1)
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 0, 0, 1, 1)
        self.main_if_infos_table = QtWidgets.QTableWidget(self.centralwidget)
        self.main_if_infos_table.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.main_if_infos_table.sizePolicy().hasHeightForWidth())
        self.main_if_infos_table.setSizePolicy(sizePolicy)
        self.main_if_infos_table.setObjectName("main_if_infos_table")
        self.main_if_infos_table.setColumnCount(5)
        self.main_if_infos_table.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.main_if_infos_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_if_infos_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_if_infos_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_if_infos_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.main_if_infos_table.setHorizontalHeaderItem(4, item)
        self.gridLayout.addWidget(self.main_if_infos_table, 4, 0, 1, 2)
        self.main_footer_text = QtWidgets.QTextBrowser(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.main_footer_text.sizePolicy().hasHeightForWidth())
        self.main_footer_text.setSizePolicy(sizePolicy)
        self.main_footer_text.setMinimumSize(QtCore.QSize(0, 75))
        self.main_footer_text.setMaximumSize(QtCore.QSize(16777215, 75))
        self.main_footer_text.setObjectName("main_footer_text")
        self.gridLayout.addWidget(self.main_footer_text, 5, 0, 1, 2)
        self.infos_detail_tab = QtWidgets.QTabWidget(self.centralwidget)
        self.infos_detail_tab.setObjectName("infos_detail_tab")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.tab)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.infos_detail_application_tree = QtWidgets.QTreeWidget(self.tab)
        self.infos_detail_application_tree.setObjectName("infos_detail_application_tree")
        self.horizontalLayout.addWidget(self.infos_detail_application_tree)
        self.infos_detail_tab.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.tab_2)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.infos_detail_transport_tree = QtWidgets.QTreeWidget(self.tab_2)
        self.infos_detail_transport_tree.setObjectName("infos_detail_transport_tree")
        self.horizontalLayout_2.addWidget(self.infos_detail_transport_tree)
        self.infos_detail_tab.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.tab_3)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.infos_detail_network_tree = QtWidgets.QTreeWidget(self.tab_3)
        self.infos_detail_network_tree.setObjectName("infos_detail_network_tree")
        self.horizontalLayout_3.addWidget(self.infos_detail_network_tree)
        self.infos_detail_tab.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.tab_4)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.infos_detail_datalink_tree = QtWidgets.QTreeWidget(self.tab_4)
        self.infos_detail_datalink_tree.setObjectName("infos_detail_datalink_tree")
        self.horizontalLayout_4.addWidget(self.infos_detail_datalink_tree)
        self.infos_detail_tab.addTab(self.tab_4, "")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setObjectName("tab_5")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.tab_5)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.infos_detail_physical_tree = QtWidgets.QTreeWidget(self.tab_5)
        self.infos_detail_physical_tree.setObjectName("infos_detail_physical_tree")
        self.horizontalLayout_5.addWidget(self.infos_detail_physical_tree)
        self.infos_detail_tab.addTab(self.tab_5, "")
        self.gridLayout.addWidget(self.infos_detail_tab, 7, 0, 1, 2)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem1)
        self.main_image_label = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.main_image_label.sizePolicy().hasHeightForWidth())
        self.main_image_label.setSizePolicy(sizePolicy)
        self.main_image_label.setObjectName("main_image_label")
        self.horizontalLayout_6.addWidget(self.main_image_label)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem2)
        self.gridLayout.addLayout(self.horizontalLayout_6, 1, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 753, 22))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuView = QtWidgets.QMenu(self.menubar)
        self.menuView.setObjectName("menuView")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setIconSize(QtCore.QSize(32, 32))
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionClose = QtWidgets.QAction(MainWindow)
        self.actionClose.setObjectName("actionClose")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionSave = QtWidgets.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionColor_Rules = QtWidgets.QAction(MainWindow)
        self.actionColor_Rules.setObjectName("actionColor_Rules")
        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addAction(self.actionClose)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.menuView.addAction(self.actionColor_Rules)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuView.menuAction())

        self.retranslateUi(MainWindow)
        self.infos_detail_tab.setCurrentIndex(4)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        item = self.infos_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.infos_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.infos_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Source"))
        item = self.infos_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.infos_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.infos_table.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length"))
        item = self.infos_table.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Info"))
        self.main_header_label.setText(_translate("MainWindow", "Welcome!"))
        item = self.main_if_infos_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "index"))
        item = self.main_if_infos_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Name"))
        item = self.main_if_infos_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "MAC"))
        item = self.main_if_infos_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "IPv4"))
        item = self.main_if_infos_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "IPv6"))
        self.main_footer_text.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:14pt; font-weight:600;\">Github: https://github.com/Coming98/jcSniffer</span></p>\n"
"<p align=\"right\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'-apple-system\',\'BlinkMacSystemFont\',\'Segoe UI\',\'Helvetica\',\'Arial\',\'sans-serif\',\'Apple Color Emoji\',\'Segoe UI Emoji\'; font-size:12pt; font-weight:600; color:#57606a; background-color:#ffffff;\">© 2022 ComingPro</span></p></body></html>"))
        self.infos_detail_tab.setTabText(self.infos_detail_tab.indexOf(self.tab), _translate("MainWindow", "Application"))
        self.infos_detail_tab.setTabText(self.infos_detail_tab.indexOf(self.tab_2), _translate("MainWindow", "Transport"))
        self.infos_detail_tab.setTabText(self.infos_detail_tab.indexOf(self.tab_3), _translate("MainWindow", "Network"))
        self.infos_detail_tab.setTabText(self.infos_detail_tab.indexOf(self.tab_4), _translate("MainWindow", "DataLink"))
        self.infos_detail_tab.setTabText(self.infos_detail_tab.indexOf(self.tab_5), _translate("MainWindow", "Physical"))
        self.main_image_label.setText(_translate("MainWindow", "Main_Image_label"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuView.setTitle(_translate("MainWindow", "View"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionClose.setText(_translate("MainWindow", "Close"))
        self.actionExit.setText(_translate("MainWindow", "Exit"))
        self.actionSave.setText(_translate("MainWindow", "Save"))
        self.actionColor_Rules.setText(_translate("MainWindow", "Color Rules"))

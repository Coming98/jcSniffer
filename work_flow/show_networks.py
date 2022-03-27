#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File         :   show_networks.py
@Author       :   JC
@Contact      :   jcqueue@gmail.com
@Department   :   INSTITUTE OF INFORMATION ENGINEERING, CAS
@Desc         :   
'''
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QTableWidgetItem
from scapy.all import ifaces

MAIN_IMAGE_PATH = './resource/images/main.png'



def init_view(window):
    window.taggle_info_window(True)
    main_image_obj = QPixmap(MAIN_IMAGE_PATH)
    window.main_image_label.setPixmap(main_image_obj)
    window.main_image_label.setScaledContents(True)  # 让图片自适应label大小

def try_get_content(data, index, default):
    try:
        res = data[index]
        return res
    except:
        return default

def get_contents(line):
    idxes = [0, 9, 16, 58, 77, 94, 119]
    contents = []
    for i in range(len(idxes) - 1):
        raw_content = line[idxes[i]:idxes[i+1]]
        content = raw_content.strip()
        
        contents.append('None' if(len(content) == 0) else content)

    return contents


def get_if_infos():
    info_lines = str(ifaces).split('\n')


    if_infos = []
    for line in info_lines[1:]:
        contents = get_contents(line)
        print(contents)
        if_info = {
            'source': contents[0],
            'index': contents[1],
            'name': contents[2],
            'MAC': contents[3],
            'ipv4': contents[4],
            'ipv6': contents[5]
        }
        if(if_info['MAC'] == 'None'):
            if_info['valid'] = False
        else:
            if_info['valid'] = True
        
        if_infos.append(if_info)

    return if_infos

def update_view_if_infos(window):
    for if_info in window.if_infos:
        if(not if_info['valid']): continue
        row_number = window.main_if_infos_table.rowCount()
        window.main_if_infos_table.setRowCount(row_number + 1)

        table = window.main_if_infos_table
        items = ['index', 'name', 'MAC', 'ipv4', 'ipv6']
        for index, item in enumerate(items):
            table.setItem(row_number, index, QTableWidgetItem(if_info[item]))

def update_double_clicked_event(window):
    table = window.main_if_infos_table
    table.itemDoubleClicked.connect(window.main_if_infos_table_doubleClicked)



def main(window):

    init_view(window)

    window.if_infos = get_if_infos()

    update_view_if_infos(window)

    update_double_clicked_event(window)

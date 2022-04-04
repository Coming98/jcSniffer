
from PyQt5.QtWidgets import QTableWidgetItem, QTreeWidgetItem
from scapy.all import hexdump, ifaces
import time
import sys
from PyQt5.QtGui import QBrush, QColor
sys.path.append('./')
from work_flow import analysis_packet
from view import init_view
import re

def get_download_file_load(pkts, target_infos, src, dst):
    target_infos
    file_load = b""
    file_load_seq = []
    for pkt in pkts:
        if(not (pkt.haslayer('Raw') and pkt.haslayer('IP') and pkt['IP'].src == src and pkt['IP'].dst == dst)): continue
        load = pkt.load
        ack = pkt.ack
        seq = pkt.seq
        if b'200 OK' not in load and ack == target_infos[0] and seq not in file_load_seq:
            file_load += load
            file_load_seq.append(seq)
            if(len(file_load) == target_infos[2]):
                return file_load
            if(len(file_load) > target_infos[2]):
                print("数据过长")
                return None
    print("数据不够")
    return None
    
def get_download_target_infos(pkts, src, dst):
    for pkt in pkts:
        if(not (pkt.haslayer('Raw') and pkt.haslayer('IP') and pkt['IP'].src == src and pkt['IP'].dst == dst)): continue
        load = pkt.load
        ack = pkt.ack
        if(b'200 OK' not in load): continue
        meta_type, length = re.search(r'Content-type: (.*?)\r\n.*?Content-Length: (.*?)\r\n', load.decode()).groups()
        file_type = meta_type.split('/')[-1]
        length = int(length)
        return (ack, file_type, length)
    return (None, )
def check_download(window, packet_number, packet_infos):
    (source, destination, protocol, info) = packet_infos
    # res = re.search(r'GET(.*?)jp[e]?g', info)
    res = re.search(r'GET (.*?) HTTP/1.[01]', info)
    if(protocol == 'HTTP' and res):
        window.download_name = res.group(1).split('/')[-1]
        window.download_src = destination
        window.download_dst = source
        window.download_begin_number = int(packet_number) + 1
        init_view.update_welcome_toolbar(window, "downloadable")
        print("target", window.download_name)
    else:
        window.download_name = None
        window.download_src = None
        window.download_dst = None
        window.download_begin_number = None
        init_view.update_welcome_toolbar(window, "undownloadable")

def show_packet_items_table(window):
    packet_items_table = window.packet_items_table
    row_number = packet_items_table.rowCount()

    packet_items = window.packet_items

    for item in packet_items[-1:]:
        packet_items_table.setRowCount(row_number + 1)

        cols = ['No.', 'Time', 'Source', 'Destinaiton', 'Protocol', 'Length', 'Info']
        color = window.proto2color.get(str(item['Protocol']).upper(), (255, 255, 255, 255))
        for index, col in enumerate(cols):
            packet_items_table.setItem(row_number, index, QTableWidgetItem(str(item[col])))
            packet_items_table.item(row_number, index).setBackground(QBrush(QColor(*color)))

        if(not check_packet_by_filter(item, window.filters)): 
            packet_items_table.setRowHidden(row_number, True)
        else:
            window.rowcount += 1

        row_number += 1 

def _single_filter(target, filter, func=None):
    if(len(filter) == 0 or '*' in filter): return True
    else:
        if(target is None): return False
        if(func is not None): target = func(target)
        if(target not in filter): return False
        return True

def check_packet_by_filter(packet_item, filters):
    if(filters is None): return True
    status = []
    for filter in filters:
        src, dst, sport, dport, protocol = [ packet_item.get(name) for name in ('src', 'dst', 'sport', 'dport', 'Protocol') ]

        flag = _single_filter(protocol.upper(), filter['protocol'])
        if(not flag): 
            status.append(False)
            continue

        flag = _single_filter(sport, filter['sport'], func=int)
        if(not flag): 
            status.append(False)
            continue

        flag = _single_filter(dport, filter['dport'], func=int)
        if(not flag): 
            status.append(False)
            continue

        flag_s = _single_filter(sport, filter['port'], func=int) # 单条件筛选
        flag_d = _single_filter(dport, filter['port'], func=int) # 单条件筛选

        if(not (flag_s or flag_d) ):
            status.append(False)
            continue

        flag = _single_filter(src, filter['src'])
        if(not flag): 
            status.append(False)
            continue

        flag = _single_filter(dst, filter['dst'])
        if(not flag): 
            status.append(False)
            continue

        flag_s = _single_filter(src, filter['ip']) # 单条件筛选
        flag_d = _single_filter(dst, filter['ip']) # 单条件筛选

        if(not (flag_s or flag_d) ):
            status.append(False)
            continue
    
        status.append(True)
        break

    if(status[-1] == True):
        return True
    return False


        

def show_packet_items_table_by_filter(window):
    if(window.sniffThread is None): return
    start_flag = False
    if(window.sniffThread.isRunning() == True):
        window.sniffThread.terminate()
        start_flag = True

    table = window.packet_items_table
    filters = window.filters
    packet_items = window.packet_items

    show_count = 0
    for row in range(len(packet_items)):
        flag = check_packet_by_filter(packet_items[row], filters)
        if(not flag):
            table.setRowHidden(row, True)
        else:
            table.setRowHidden(row, False)
            show_count += 1
    window.rowcount = show_count


    start_flag and window.sniffThread.start()
    


def show_packet_detail_tab(window, packet, packet_number):
    # HEX DATA
    handle_hexdata(window, window.packet_detail_hexdata_text, packet)

    # Physical data
    handle_physical(window, window.packet_detail_physical_tree, packet, packet_number)

    # Datalink data
    handle_datalink(window, window.packet_detail_datalink_tree, packet)

    # Network data - Application data
    handle_network(window, packet)

def update_infos(target, infos, header=False):
    if(header):
        # print(infos)
        target.headerItem().setText(0, infos['header'])
    else:
        target.setText(0, infos['header'])
        target.setToolTip(0, 'Tips')

    if('childs' in infos):
        for info in infos['childs']:
            child_item = QTreeWidgetItem(target)
            update_infos(child_item, info)

# IP / IPv6 / ARP
def handle_network(window, packet):
    infos_list = analysis_packet.analysis_network(packet, brief=False)

    if(infos_list is not None):
        tab_list = [window.tab_network, window.tab_transport, window.tab_application]
        targets = [window.packet_detail_network_tree, window.packet_detail_transport_tree, window.packet_detail_application_tree]
        for target, tab, infos in zip(targets, tab_list, infos_list):
            target.clear()
            update_infos(target, infos, header=True)
            window.packet_detail_tab.insertTab(0, tab, infos['brief_name'])


def handle_datalink(window, target, packet):
    target.clear()
    infos = {
        'header': f'Ethernet, Src: {packet.src}, Dst: {packet.dst}',
        'childs': [
            {'header': f'Destination: {packet.dst}'},
            {'header': f'Source: {packet.src}'},
            {'header': f'Type: {hex(packet.type)}'},
        ]
    }
    update_infos(target, infos, header=True)
    window.packet_detail_tab.insertTab(0, window.tab_datalink, 'DataLink')

def handle_physical(window, target, packet, packet_number):
    target.clear()
    length = len(packet)
    arrival_timestamp = packet.time
    arrival_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
    if(window.if_name is not None):
        interface = ifaces.dev_from_name(window.if_name)
        interface_detail = {
                'header': f'Interface id: {interface.index} ({interface.network_name})',
                'childs': [
                    {'header': f'Interface id: {interface.index}'},
                    {'header': f'Interface name: {interface.name}'},
                    {'header': f'Interface network_name: {interface.network_name}'},
                    {'header': f'Interface description: {interface.description}'},
                    {'header': f'Interface ipv4: {interface.ip}'},
                    {'header': f'Interface ipv6: {", ".join(interface.ips[6])}'},
                ]
            }
    else:
        interface_detail = {
                'header': f'External unknown Interface',
            }
    infos = {
        'header': f'Frame {packet_number}: {length} bytes on wire ({length*8} bits), captured on' + f'interface {interface.network_name}' if window.if_name is not None else 'External unknown Interface',
        'childs' : [
            interface_detail, 
            {'header': f'Arrival time: {arrival_time}'},
            {'header': f'Time since reference or first frame: {arrival_timestamp - window.start_time:.3f} seconds'},
            {'header': f'Frame number: {packet_number}'},
            {'header': f'Frame length: {length} bytes ({length*8} bits)'},
        ]
    }
    update_infos(target, infos, header=True)
    window.packet_detail_tab.insertTab(0, window.tab_physical, 'Physical')

def handle_hexdata(window, target, packet):
    target.setText(hexdump(packet, dump=True))
    window.packet_detail_tab.insertTab(0, window.tab_hexdata, 'Hex Data')
    
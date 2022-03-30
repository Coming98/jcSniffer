
from PyQt5.QtWidgets import QTableWidgetItem, QTreeWidgetItem
from scapy.all import hexdump, ifaces
import time

def show_packet_items_table(window):
    packet_items_table = window.packet_items_table
    row_number = packet_items_table.rowCount()

    packet_items = window.packet_items

    for item in packet_items[row_number:]:
        packet_items_table.setRowCount(row_number + 1)

        cols = ['No.', 'Time', 'Source', 'Destinaiton', 'Protocol', 'Length', 'Info']
        for index, col in enumerate(cols):
            packet_items_table.setItem(row_number, index, QTableWidgetItem(str(item[col])))

        row_number += 1 

def show_packet_detail_tab(window, packet, packet_number):
    # HEX DATA
    handle_hexdata(window, window.packet_detail_hexdata_text, packet)

    # Physical data
    handle_physical(window, window.packet_detail_physical_tree, packet, packet_number)

    # Datalink data
    handle_datalink(window, window.packet_detail_datalink_tree, packet)

    # Network data
    handle_network(window, window.packet_detail_network_tree, packet)

    # Transport data
    handle_transport(window, window.packet_detail_transport_tree, packet)

    # Application data
    handle_application(window, window.packet_detail_application_tree, packet)

def update_infos(target, infos, header=False):
    if(header):
        target.headerItem().setText(0, infos['header'])
    else:
        target.setText(0, infos['header'])

    if('childs' in infos):
        for info in infos['childs']:
            child_item = QTreeWidgetItem(target)
            update_infos(child_item, info)

def handle_application(window, target, packet):
    window.tab_application.setHidden(True)

def handle_transport(window, target, packet):
    window.tab_transport.setHidden(True)

def handle_network(window, target, packet):
    target.clear()
    # infos = get_network_infos(packet)
    infos = None
    if(infos is None):
        window.tab_network.setHidden(True)
    else:
        update_infos(target, packet)

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
    interface = ifaces.dev_from_name(window.if_name)
    infos = {
        'header': f'Frame {packet_number}: {length} bytes on wire ({length*8} bits), captured on interface {interface.network_name}',
        'childs' : [
            {
                'header': f'Interface id: {interface.index} ({interface.network_name})',
                'childs': [
                    {'header': f'Interface id: {interface.index}'},
                    {'header': f'Interface name: {interface.name}'},
                    {'header': f'Interface network_name: {interface.network_name}'},
                    {'header': f'Interface description: {interface.description}'},
                    {'header': f'Interface ipv4: {interface.ip}'},
                    {'header': f'Interface ipv6: {", ".join(interface.ips[6])}'},
                ]
            }, 
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
    

from PyQt5.QtWidgets import QTableWidgetItem

def show(window):
    packet_items_table = window.packet_items_table
    row_number = packet_items_table.rowCount()

    packet_items = window.packet_items

    for item in packet_items[row_number:]:
        packet_items_table.setRowCount(row_number + 1)

        cols = ['No.', 'Time', 'Source', 'Destinaiton', 'Protocol', 'Length', 'Info']
        for index, col in enumerate(cols):
            packet_items_table.setItem(row_number, index, QTableWidgetItem(str(item[col])))

        row_number += 1 
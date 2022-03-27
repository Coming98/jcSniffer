
from PyQt5.QtWidgets import QTableWidgetItem

def show(window):
    infos_table = window.infos_table
    row_number = infos_table.rowCount()

    packet_items = window.packet_items

    for item in packet_items[row_number:]:
        infos_table.setRowCount(row_number + 1)

        cols = ['No.', 'Time', 'Source', 'Destinaiton', 'Protocol', 'Length', 'Info']
        for index, col in enumerate(cols):
            infos_table.setItem(row_number, index, QTableWidgetItem(str(item[col])))

        row_number += 1 
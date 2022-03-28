from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

class TableViewer(QMainWindow):
    def __init__(self, parent=None):
        super(TableViewer, self).__init__(parent)
        self.table = QTableWidget(3, 3)
        for row in range (0,3):
            for column in range(0,3):
                item = QTableWidgetItem("This is cell {} {}".format(row+1, column+1))
                self.table.setItem(row, column, item)
        self.setCentralWidget(self.table)

        self.table.setMouseTracking(True)

        self.current_hover = [0, 0]
        self.table.cellEntered.connect(self.cellHover)


# def main_if_infos_table_cellHover(self, row, _):
#     table = self.main_if_infos_table
#     column_count = table.columnCount()

#     cur_row = row
#     old_row = self.main_if_infos_table_cur_hover_row

#     cur_items = [table.item(cur_row, idx) for idx in range(column_count)]
#     old_items = [table.item(old_row, idx) for idx in range(column_count)]

#     if cur_row != old_row:
#         for item in old_items:
#             item.setBackground(QBrush(QColor('white')))
#         for item in cur_items:
#             item.setBackground(QBrush(QColor('steelblue')))

#     self.main_if_infos_table_cur_hover_row = cur_row



# # Hover 一行的效果
# table.setMouseTracking(True)
# window.main_if_infos_table_cur_hover_row = 0
# table.cellEntered.connect(window.main_if_infos_table_cellHover)

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    tv = TableViewer()
    tv.show()
    sys.exit(app.exec_())
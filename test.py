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




if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    tv = TableViewer()
    tv.show()
    sys.exit(app.exec_())
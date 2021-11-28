from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5 import uic
from PyQt5.QtWidgets import *
from mainwindow import Ui_MainWindow
import sys


class Loader:
    def __init__(self):
        self.ui = uic.loadUi("main_window.ui")
        self.modify()

        # 退出
        self.ui.action_exit.triggered.connect(self.exit)

    def exit(self):
        Reply = QMessageBox.question(self.ui, 'Message',
                                     "Are you sure to quit?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if Reply == QMessageBox.Yes:
            self.ui.close()

    def modify(self):
        self.ui.table_wrapper.auto_scroll = True
        self.ui.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ui.table.horizontalHeader().setStretchLastSection(True)
        QTableWidget.resizeColumnsToContents(self.ui.table)
        QTableWidget.resizeRowsToContents(self.ui.table)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # 显示窗口
    loader = Loader()
    loader.ui.show()
    sys.exit(app.exec_())

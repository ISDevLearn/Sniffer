from scapy.all import *
from PyQt5.QtWidgets import *

global ui


def modify():
    set_table()
    get_nif(ui.if_box)  # 获取网卡
    set_toolbar()


def get_nif(if_box: QComboBox):
    if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
    if_box.addItems(if_list)


def set_table():
    ui.table_wrapper.auto_scroll = True
    ui.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    ui.table.horizontalHeader().setStretchLastSection(True)
    QTableWidget.resizeColumnsToContents(ui.table)
    QTableWidget.resizeRowsToContents(ui.table)


def set_toolbar():
    ui.action_exit.triggered.connect(exit)
    ui.action_exit_2.triggered.connect(exit)


def exit():
    reply = QMessageBox.question(ui, '温馨提示',
                                 "确定退出吗?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        ui.close()

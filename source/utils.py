from scapy.all import *
from PyQt5.QtWidgets import *
import signal
import sniffer

global ui
global s
ui: QWidget
s: sniffer.Sniffer
signals = sniffer.signals


def modify(_ui: QWidget):
    global ui
    ui = _ui
    set_table(ui.table)
    get_nif(ui.if_box)  # 获取网卡
    set_toolbar()
    set_signal()


def get_nif(if_box: QComboBox):
    if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
    if_box.addItems(if_list)


def set_table(table: QTableWidget):
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    # table.verticalScrollBar()
    QTableWidget.resizeColumnsToContents(table)
    QTableWidget.resizeRowsToContents(table)


def set_toolbar():
    ui.action_exit.triggered.connect(exit)
    ui.action_exit_2.triggered.connect(exit)
    ui.action_start.triggered.connect(start)  # test
    ui.action_stop.triggered.connect(stop)


def set_signal():
    signals.update_table.connect(add_row)


def exit():
    reply = QMessageBox.question(ui, 'Message',
                                 "Are you sure to quit?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        ui.close()


def add_row(info: list):
    table: QTableWidget = ui.table
    rows = table.rowCount()
    table.insertRow(rows)
    for i in range(7):
        table.setItem(rows, i, QTableWidgetItem(str(info[i])))
    # table.setItem(rows, 0, QTableWidgetItem(info))
    table.scrollToBottom()


def start():
    global s
    # signals.update_table.emit([1, 2, 3, 4, 5, 6, 7])
    s = sniffer.Sniffer(ui)
    s.start()


def stop():
    s.stop()

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
    initialize()  # 初始化
    set_toolbar()  # 设置工具栏操作
    set_signal()  # 设置信号


# 获取网卡
def get_nif(if_box: QComboBox):
    if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
    if_box.addItems(if_list)
    return if_list


# 检测网卡，如果没有选定的话开始按钮无法按下
def check_nif():
    if get_nif(ui.if_box):
        ui.action_start.setEnabled(True)
        ui.action_restart.setEnabled(True)
    else:
        ui.action_start.setEnabled(False)
        ui.action_restart.setEnabled(False)


# 初始化动作
def initialize():
    ui.action_stop.setEnabled(False)
    check_nif()
    ui.action_restart.setEnabled(False)
    ui.action_clean_all.setEnabled(False)
    ui.action_save_as.setEnabled(False)


# 设置信息展示表格
def set_table(table: QTableWidget):
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    # table.verticalScrollBar()
    QTableWidget.resizeColumnsToContents(table)
    QTableWidget.resizeRowsToContents(table)


# 设置工具栏操作
def set_toolbar():
    ui.action_exit.triggered.connect(exit)
    ui.action_exit_2.triggered.connect(exit)
    ui.action_start.triggered.connect(start)
    ui.action_start_2.triggered.connect(start)
    ui.action_stop.triggered.connect(stop)
    ui.action_stop_2.triggered.connect(stop)
    ui.action_clean_all.triggered.connect(clean_all)
    ui.action_clean_all_2.triggered.connect(clean_all)


# 设置信号
def set_signal():
    signals.update_table.connect(add_row)


# 退出界面
def exit():
    reply = QMessageBox.question(ui, '温馨提示',
                                 "确定退出吗?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        ui.close()


# 添加行
def add_row(info: list):
    table: QTableWidget = ui.table
    rows = table.rowCount()
    table.insertRow(rows)
    for i in range(7):
        table.setItem(rows, i, QTableWidgetItem(str(info[i])))
    # table.setItem(rows, 0, QTableWidgetItem(info))
    table.scrollToBottom()


# 开始嗅探
def start():
    global s
    # signals.update_table.emit([1, 2, 3, 4, 5, 6, 7])
    s = sniffer.Sniffer(ui)
    s.start()
    ui.action_stop.setEnabled(True)
    ui.action_start.setEnabled(False)
    ui.action_restart.setEnabled(False)
    ui.action_clean_all.setEnabled(False)
    ui.action_save_as.setEnabled(False)
    ui.action_exit.setEnabled(False)


# 停止嗅探
def stop():
    s.stop()
    check_nif()
    ui.action_stop.setEnabled(False)
    ui.action_clean_all.setEnabled(True)
    ui.action_save_as.setEnabled(True)
    ui.action_exit.setEnabled(True)


# 清除内容，目前有点寄，没有重置表格
def clean_all():
    reply = QMessageBox.question(ui, '温馨提示',
                                 "该操作将会清除所有内容！",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        ui.table.clearContents()

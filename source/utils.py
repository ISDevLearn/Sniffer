from scapy.all import *
from PyQt5.QtWidgets import *
from packet import PacketInfo
import sniffer


global ui
global s
ui: QWidget
s: sniffer.Sniffer
signals = sniffer.signals


def modify(_ui: QWidget):
    global ui
    global s
    ui = _ui
    s = sniffer.Sniffer(ui)
    set_table()
    get_nif(ui.if_box)  # 获取网卡
    initialize()  # 初始化
    set_toolbar()  # 设置工具栏操作
    set_if_box()
    set_signal()  # 设置信号


# 获取网卡
def get_nif(if_box: QComboBox):
    if_list = [nif.name for nif in get_working_ifaces() if nif.mac]
    if_box.addItems(if_list)
    return if_list


# 初始化动作
def initialize():
    ui.action_start.setEnabled(False)
    ui.action_stop.setEnabled(False)
    ui.action_restart.setEnabled(False)
    ui.action_clean_all.setEnabled(False)
    ui.action_save_as.setEnabled(False)


# 设置信息展示表格
def set_table():
    ui.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    ui.table.setColumnWidth(0, 50)
    ui.table.setColumnWidth(2, 150)
    ui.table.setColumnWidth(3, 150)
    ui.table.setColumnWidth(4, 100)
    ui.table.setColumnWidth(5, 50)
    ui.table.horizontalHeader().setStretchLastSection(True)
    ui.table.setStyleSheet('QTableWidget::item:selected{background-color: #ACACAC}')
    ui.table.itemClicked.connect(show_detail)
    ui.table.itemClicked.connect(show_hex)
    # ui.table.itemClicked.connect(change_color)


# 设置工具栏操作
def set_toolbar():
    ui.action_exit.triggered.connect(exit)
    ui.action_start.triggered.connect(start)
    ui.action_stop.triggered.connect(stop)
    ui.action_clean_all.triggered.connect(clean_all)
    ui.action_restart.triggered.connect(restart)


def set_if_box():
    ui.if_box.currentIndexChanged.connect(check_nif)


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


# 检测网卡，如果没有选定的话开始按钮无法按下
def check_nif(index):
    if index != 0 and not s.is_running:
        ui.action_start.setEnabled(True)
        ui.action_restart.setEnabled(True)
    else:
        ui.action_start.setEnabled(False)
        ui.action_restart.setEnabled(False)


# 添加行
def add_row(packet_info: PacketInfo):
    table: QTableWidget = ui.table
    rows = table.rowCount()
    table.insertRow(rows)
    headers = ['number', 'time', 'src', 'dst', 'protocol', 'length', 'info']
    for i, header in enumerate(headers):
        item = QTableWidgetItem(str(packet_info.__dict__[header]))
        item.setBackground(packet_info.color)
        table.setItem(rows, i, item)
    table.scrollToBottom()


def clear():
    ui.table.clearContents()
    ui.table.setRowCount(0)
    ui.table.detail_tree.clear()
    ui.table.hex_text.clear()


# 开始嗅探
def start():
    s.start()
    ui.action_stop.setEnabled(True)
    ui.action_start.setEnabled(False)
    ui.action_restart.setEnabled(False)
    ui.action_clean_all.setEnabled(False)
    ui.action_save_as.setEnabled(False)
    ui.action_exit.setEnabled(False)
    ui.action_open_file.setEnabled(False)
    ui.action_filter.setEnabled(True)


# 重新开始
def restart():
    clear()
    start()


# 停止嗅探
def stop():
    s.stop()
    ui.action_stop.setEnabled(False)
    ui.action_restart.setEnabled(True)
    ui.action_start.setEnabled(True)
    ui.action_clean_all.setEnabled(True)
    ui.action_save_as.setEnabled(True)
    ui.action_open_file.setEnabled(True)
    ui.action_filter.setEnabled(True)
    ui.action_exit.setEnabled(True)


# 清除内容
def clean_all():
    reply = QMessageBox.question(ui, '温馨提示',
                                 "该操作将会清除所有内容！",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    if reply == QMessageBox.Yes:
        clear()


# 展示详细信息
def show_detail(item: QTableWidgetItem):
    tree: QTreeWidget = ui.detail_tree
    tree.clear()
    row = item.row()
    info = s.packets[row].detail_info
    for layer, layer_info in info.items():
        root = QTreeWidgetItem(tree)
        root.setText(0, layer)
        if layer_info:
            for key, value in layer_info.items():
                if value is None:
                    value = ''
                node = QTreeWidgetItem(root)
                node.setText(0, key)
                node.setText(1, value)
                root.addChild(node)
    tree.expandAll()


# 展示hex信息
def show_hex(item: QTableWidgetItem):
    row = item.row()
    text: QTextBrowser = ui.hex_text
    text.clear()
    hex_info = s.packets[row].hex_info
    text.setText(hex_info)


# 有点寄 先不用了
def change_color(item: QTableWidgetItem):
    current_color = item.background().color()
    color = hex(current_color.darker(120).rgb())[4:10]
    ui.table.setStyleSheet('QTableWidget::item:selected{background-color: ##ACACAC}' + color + '}')
    print(color)
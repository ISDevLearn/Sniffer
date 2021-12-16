from scapy.all import *
from PyQt5.QtWidgets import *
from packet import PacketInfo
from searcher import Searcher
import sniffer
import signal


ui: QWidget
s: sniffer.Sniffer
signals: signal.Signals


def modify(_ui: QWidget):
    global ui
    global s
    global signals
    ui = _ui
    s = sniffer.Sniffer(ui)
    signals = s.signals
    set_table()
    get_nif(ui.if_box)  # 获取网卡
    initialize()  # 初始化
    set_toolbar()  # 设置工具栏操作
    set_if_box()
    set_signal()  # 设置信号
    set_searcher()


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
    ui.action_reassemble.triggered.connect(reassemble)


def set_if_box():
    ui.if_box.currentIndexChanged.connect(check_nif)


def set_searcher():
    search_button = ui.search_button
    search_button.clicked.connect(search)
    search_button.setShortcut('Return')


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


# 清除信息
def clear():
    clear_table()
    s.clear()


def clear_table():
    ui.table.clearContents()
    ui.table.setRowCount(0)
    ui.detail_tree.clear()
    ui.hex_text.clear()


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
    number = int(ui.table.item(row, 0).text())-1
    info = s.packets[number].detail_info
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
    number = int(ui.table.item(row, 0).text()) - 1
    text: QTextBrowser = ui.hex_text
    text.clear()
    hex_info = s.packets[number].hex_info
    text.setText(hex_info)


# 包重组
def reassemble():
    table: QTableWidget = ui.table
    assemble_rows = table.selectedIndexes()
    row_set = set(tmp_row.row() for tmp_row in assemble_rows)
    if row_set:
        reassemble_packet_list = []
        for tmp_row in row_set:
            number = int(ui.table.item(tmp_row, 0).text()) - 1
            reassemble_packet_list.append(s.packets[number].detail_info)
        # print(reassemble_packet_list)
        reassemble_packet_dict = s.reassemble_packet(reassemble_packet_list)



def search():
    search_text: QLineEdit = ui.search_text
    text = search_text.text()
    clear_table()
    if text == '':
        for p in s.packets:
            add_row(p)
    else:
        searcher = Searcher(s.packets, text)
        result = searcher.search()
        for p in result:
            add_row(p)

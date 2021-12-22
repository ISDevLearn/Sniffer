from scapy.all import *
from PyQt5.QtWidgets import *
from packet import PacketInfo
from searcher import Searcher
from reassembler import Reassembler
import sniffer
import filter
import json
import time
import ast


ui: QWidget
s: sniffer.Sniffer
reassembler: Reassembler


def modify(_ui: QWidget):
    global ui
    global s
    global reassembler
    ui = _ui
    s = sniffer.Sniffer(ui)
    reassembler = Reassembler()
    # signals = s.signals
    set_table()
    set_reassemble_table()
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


# 设置重组信息表格
def set_reassemble_table():
    ui.reassemble_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    ui.reassemble_table.setColumnWidth(0, 50)
    ui.reassemble_table.setColumnWidth(1, 50)
    ui.reassemble_table.setColumnWidth(2, 50)
    ui.reassemble_table.setColumnWidth(3, 50)
    ui.reassemble_table.setColumnWidth(4, 50)
    ui.reassemble_table.horizontalHeader().setStretchLastSection(True)
    ui.reassemble_table.setStyleSheet('QTableWidget::item:selected{background-color: #ACACAC}')
    ui.reassemble_table.itemClicked.connect(show_reass_detail)
    # ui.reassemble_table.itemClicked.connect(show_hex)


# 设置工具栏操作
def set_toolbar():
    ui.action_exit.triggered.connect(exit)
    ui.action_start.triggered.connect(start)
    ui.action_stop.triggered.connect(stop)
    ui.action_clean_all.triggered.connect(clean_all)
    ui.action_restart.triggered.connect(restart)
    ui.action_reassemble.triggered.connect(reassemble)
    ui.action_save_as.triggered.connect(save)
    ui.action_open_file.triggered.connect(load)
    ui.action_show_details.triggered.connect(lambda: ui.tab.setCurrentIndex(0))
    ui.action_filter.triggered.connect(lambda: ui.tab.setCurrentIndex(3))
    ui.action_tcp_to_file.triggered.connect(file_reassemble)


def set_if_box():
    ui.if_box.currentIndexChanged.connect(check_nif)


def set_searcher():
    search_button = ui.search_button
    search_button.clicked.connect(search)
    search_button.setShortcut('Return')


# 设置信号
def set_signal():
    s.signals.update_table.connect(add_row)
    reassembler.signals.update_reassemble_table.connect(add_reassrow)


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


# 添加重组行
def add_reassrow(packet_info: PacketInfo):
    table: QTableWidget = ui.reassemble_table
    rows = table.rowCount()
    table.insertRow(rows)
    headers = ['number', 'src', 'dst', 'protocol', 'length', 'info']
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
    ui.reassemble_table.clearContents()
    ui.reassemble_table.setRowCount(0)


# 开始嗅探
def start():
    f = get_filter()
    s.set_filter(f.translate())
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
        ui.action_save_as.setEnabled(False)


# 展示详细信息
def show_detail(item: QTableWidgetItem):
    tree: QTreeWidget = ui.detail_tree
    tab: QTabWidget = ui.tab
    tree.clear()
    row = item.row()
    number = int(ui.table.item(row, 0).text()) - 1
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
    tab.setCurrentIndex(0)


def show_reass_detail(item: QTableWidgetItem):
    tree: QTreeWidget = ui.detail_tree
    tab: QTabWidget = ui.tab
    tree.clear()
    row = item.row()
    number = int(ui.reassemble_table.item(row, 0).text()) - 1
    info = reassembler.result_list[number]
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
    tab.setCurrentIndex(0)


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
    tab: QTabWidget = ui.tab
    assemble_rows = table.selectedIndexes()
    row_set = set(tmp_row.row() for tmp_row in assemble_rows)
    if len(row_set) >= 2:
        reassemble_packet_list = []
        for tmp_row in row_set:
            number = int(ui.table.item(tmp_row, 0).text()) - 1
            reassemble_packet_list.append(s.packets[number])
        try:
            ui.reassemble_table.clearContents()
            ui.reassemble_table.setRowCount(0)
            result = reassembler.reassemble_packet(reassemble_packet_list)
            assert result == 1
        except:
            QMessageBox.warning(ui, "警告", "这些包无法进行重组...", QMessageBox.Yes)
    else:
        QMessageBox.warning(ui, "警告", "需要选择两个以上的包。", QMessageBox.Yes)
    tab.setCurrentIndex(2)


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


def get_filter():
    src = ui.filter_src.text()
    dst = ui.filter_dst.text()
    sport = ui.filter_sport.text()
    dport = ui.filter_dport.text()
    protocol = ui.filter_protocol.text()
    if ui.radio_and.isChecked():
        connector = ' and '
    else:
        connector = ' or '
    return filter.Filter(src, dst, sport, dport, protocol, connector)


def save():
 try:
    save_list = []
    assemble_rows = ui.table.selectedIndexes()
    rows = set(tmp_row.row() for tmp_row in assemble_rows)
    if len(rows) > 0:
        for row in rows:
            number = int(ui.table.item(row, 0).text()) - 1
            save_list.append(s.packets[number].to_dict())
        for i, save_dict in enumerate(sorted(save_list, key=lambda x: x['time'])):
            save_dict['number'] = i + 1
        # filename = './save/' + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) + '.json'
        filepath, _ = QFileDialog.getSaveFileName(
            ui,  # 父窗口对象
            "保存文件",  # 标题
            "./save/",  # 起始目录
            "json类型 (*.json);;All Files (*)"  # 选择类型过滤项，过滤内容在括号中
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json.dumps(save_list))
                f.close()
            QMessageBox.information(ui, '提示', '保存成功', QMessageBox.Yes)
    else:
        QMessageBox.warning(ui, "警告", "至少选择一个包。", QMessageBox.Yes)
 except Exception as e:
     print(e)


def load():
    file, _ = QFileDialog.getOpenFileName(ui, "选择已保存的文件", '', '(*.json)')
    if file:
        try:
            clear()
            packet_list = []
            with open(file, 'r') as f:
                save_list = json.loads(f.read())
                for packet_dict in save_list:
                    p = PacketInfo()
                    p.from_dict(packet_dict)
                    packet_list.append(p)
                s.packets = packet_list
                f.close()
            for p in s.packets:
                add_row(p)
            QMessageBox.information(ui, '提示', '读取成功', QMessageBox.Yes)
        except Exception:
            QMessageBox.warning(ui, "警告", "读取出现异常", QMessageBox.Yes)


def file_reassemble():
    table: QTableWidget = ui.table
    assemble_rows = table.selectedIndexes()
    row_set = set(tmp_row.row() for tmp_row in assemble_rows)
    if len(row_set) >= 1:
        reassemble_packet_list = []
        for tmp_row in row_set:
            number = int(ui.table.item(tmp_row, 0).text()) - 1
            if s.packets[number].payload:
                reassemble_packet_list.append(s.packets[number])
        reassemble_packet_list = sorted(reassemble_packet_list, key=lambda x: x.time)
        raw_data = b""
        for p in reassemble_packet_list:
            raw_data += ast.literal_eval(p.payload)
        if b'\xff\xd8\xff\xe0\x00\x10JFIF' in raw_data:
            file = raw_data[raw_data.index(b'\xff\xd8\xff\xe0\x00\x10JFIF'):raw_data.index(b'\xff\xd9')+2]
            with open('./testfile/image.jpg', 'wb') as f:
                f.write(file)

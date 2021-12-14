from PyQt5.QtGui import *
from patterns import *
import re
import json


class PacketInfo:

    def __init__(self, number, time, src, dst, protocol, length, info, raw_data, hex_info):

        self.number = number
        self.time = time
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.info = info
        self.detail_info = {}
        self.raw_data = raw_data
        self.hex_info = hex_info
        self.color = None

        self.get_color()
        self.get_detail()

    def get_color(self):
        if self.protocol == 'TCP':
            self.color = QColor('#E7E6FF')
        elif self.protocol == 'UDP' or self.protocol == 'DNS':
            self.color = QColor('#DAEEFF')
        elif self.protocol == 'ICMP':
            self.color = QColor('#FCE0FF')
        elif self.protocol == 'ARP':
            self.color = QColor('#FAF0D7')
        else:
            self.color = QColor('#FFFFFF')

    def get_detail(self):
        # print(self.raw_data)
        pattern = r'###\[ (\w+) \]###'
        layers = re.findall(pattern, self.raw_data)
        self.detail_info = self.detail_info.fromkeys(layers)
        if 'Ethernet' in layers:
            match = re.search(ethernet_pattern, self.raw_data)
            self.detail_info['Ethernet'] = {'dst(目的地址)': match.group(1),
                                            'src(源地址)': match.group(2),
                                            'type(类型)': match.group(3)}
        if 'IP' in layers:
            match = re.search(ip_pattern, self.raw_data)
            attributes = ['version(版本)', 'ihl(报头长度)', 'tos(服务类型)', 'len(总长度)', 'id(标识)', 'flags(分段标志)',
                          'frag(段偏移)', 'ttl(生存期)', 'proto(协议)', 'chksum(校验和)', 'src(源地址)', 'dst(目的地址)']
            self.detail_info['IP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['IP'][attr] = match.group(i + 1)
        if 'TCP' in layers:
            match = re.search(tcp_pattern, self.raw_data)
            attributes = ['sport(源端口)', 'dport(目的端口)', 'seq(序号)', 'ack(确认号)', 'dataofs(数据偏移)',
                          'reserved(保留位)', 'flags(标志位)', 'window(窗口大小)', 'chksum(校验和)', 'urgptr(紧急指针)',
                          'options(选项)']
            self.detail_info['TCP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['TCP'][attr] = match.group(i + 1)
        if 'UDP' in layers:
            match = re.search(udp_pattern, self.raw_data)
            attributes = ['sport(源端口)', 'dport(目的端口)', 'len(长度)', 'chksum(校验和)']
            self.detail_info['UDP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['UDP'][attr] = match.group(i + 1)
        if 'ARP' in layers:
            match = re.search(arp_pattern, self.raw_data)
            attributes = ['hwtype(硬件类型)', 'ptype(协议类型)', 'hwlen(硬件地址长度)', 'plen(协议长度)', 'op(操作类型)',
                          'hwsrc(源MAC地址)', 'psrc(源IP地址)', 'hwdst(目的MAC地址)', 'pdst(目的IP地址)']
            self.detail_info['ARP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['ARP'][attr] = match.group(i + 1)
        if 'ICMP' in layers:
            match = re.search(icmp_pattern, self.raw_data)
            attributes = ['type(类型)', 'code(代码)', 'chksum(校验和)', 'id(标识)', 'seq(序号)', 'unused(未使用)']
            self.detail_info['ICMP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['ICMP'][attr] = match.group(i + 1)
        if 'Raw' in layers:
            match = re.search(raw_pattern, self.raw_data)
            self.detail_info['Raw'] = {}
            if match:
                self.detail_info['Raw']['load'] = match.group(1)
            else:
                self.detail_info['Raw']['load'] = ''
        if 'Padding' in layers:
            match = re.search(padding_pattern, self.raw_data)
            self.detail_info['Padding'] = {}
            if match:
                self.detail_info['Padding']['load'] = match.group(1)
            else:
                self.detail_info['Padding']['load'] = ''
        # print(self.detail_info)

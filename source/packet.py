from PyQt5.QtGui import *
from patterns import *
import re
import json


class PacketInfo:

    def __init__(self, number, time, src, dst, protocol, length, info, raw_data):

        self.number = number
        self.time = time
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.info = info
        self.detail_info = {}
        self.raw_data = raw_data
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
            self.detail_info['Ethernet'] = {'dst': match.group(1), 'src': match.group(2), 'type': match.group(3)}
        if 'IP' in layers:
            match = re.search(ip_pattern, self.raw_data)
            attributes = ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst']
            self.detail_info['IP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['IP'][attr] = match.group(i + 1)
        if 'TCP' in layers:
            match = re.search(tcp_pattern, self.raw_data)
            attributes = ['sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', 'window', 'chksum', 'urgptr', 'options']
            self.detail_info['TCP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['TCP'][attr] = match.group(i + 1)
        if 'UDP' in layers:
            match = re.search(udp_pattern, self.raw_data)
            attributes = ['sport', 'dport', 'len', 'chksum']
            self.detail_info['UDP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['UDP'][attr] = match.group(i + 1)
        if 'ARP' in layers:
            match = re.search(arp_pattern, self.raw_data)
            attributes = ['hwtype', 'ptype', 'hwlen', 'plen', 'op', 'hwsrc', 'psrc', 'hwdst', 'pdst']
            self.detail_info['ARP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['ARP'][attr] = match.group(i + 1)
        if 'ICMP' in layers:
            match = re.search(icmp_pattern, self.raw_data)
            attributes = ['type', 'code', 'chksum', 'id', 'seq', 'unused']
            self.detail_info['ICMP'] = dict.fromkeys(attributes)
            for i, attr in enumerate(attributes):
                self.detail_info['ICMP'][attr] = match.group(i + 1)
        # print(self.detail_info)



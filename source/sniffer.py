import scapy.utils
from scapy.all import *
from PyQt5.QtWidgets import *
from packet import PacketInfo
import time
import re
import signal


class Sniffer:

    def __init__(self, _ui: QWidget):
        self.signals = signal.Signals()
        self.ui: QWidget = _ui
        self.nif = ''
        self.number = 0
        self.time = 0
        self.sniffer = None
        self.is_running = False
        self.current_packet = None
        self.packets = []

    def start(self):
        self.nif = self.ui.if_box.currentText()
        if self.nif == '网卡':
            return
        self.is_running = True
        self.current_packet = None
        self.sniffer = AsyncSniffer(iface=self.nif, prn=self.handle)
        self.time = time.time()
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()
        self.is_running = False

    def clear(self):
        self.number = 0

    def get_protocol(self):
        protocol_list = self.current_packet.summary().split('/')
        # protocol_list:  ['Ether ', ' IP ', ' TCP 192.168.31.253:8051 > 175.27.204.206:https FA']
        # print(protocol_list)
        arp_protocol_list = ['ARP', 'RARP', 'DHCP']
        # arp protocol_list:  ['Ether ', ' ARP who has 192.168.31.1 says 192.168.31.253']
        for protocol in arp_protocol_list:
            if protocol in protocol_list[1]:
                return protocol
        if 'IP' in protocol_list[1]:
            if 'Raw' in protocol_list[-1] or 'Padding' in protocol_list[-1]:
                upper_protocol = protocol_list[-2]
            else:
                upper_protocol = protocol_list[-1]
            return upper_protocol.strip().split(' ')[0]
        # if 'TCP' in p.summary
        # ipv6:
        # ['Ether ', ' IPv6 ', ' UDP ', ' DNS Ans "fe80::10e1:13bd:be7:8c38" ']
        elif 'IPv6' in protocol_list[1]:
            return 'IPv6/' + protocol_list[2].strip().split(' ')[0]
        # DNS and others
        else:
            protocol = protocol_list[2].strip().split(' ')[0]
            if protocol != '':
                protocol += '/'
            protocol += protocol_list[2].split(' ')[1]
            return protocol

    def get_info(self, protocol):
        protocol_list = self.current_packet.summary().split("/")
        if "Ether" in protocol_list[0]:
            # protocol = self.get_protocol(p)
            # arp protocol_list:  ['Ether ', ' ARP who has 192.168.31.1 says 192.168.31.253']
            # ['Ether ', ' ARP is at 54:48:e6:99:c9:1c says 192.168.31.1']
            if 'ARP' in protocol:
                arp_info = protocol_list[1].strip()
                pattern_request = r'ARP who has (\S+) says (\S+)'
                pattern_reply = r'ARP is at (\S+) says (\S+)'
                if match := re.match(pattern_request, arp_info):
                    target = match.group(1)
                    sender = match.group(2)
                    info = f'Who has {target}? Tell {sender}'
                elif match := re.match(pattern_reply, arp_info):
                    mac = match.group(1)
                    sender = match.group(2)
                    info = f'{sender} is at {mac}'
                else:
                    info = protocol_list[1].strip()
            # DNS protocol_list:  ['Ether ', ' IP ', ' UDP ', ' DNS Qry "b\'lb._dns-sd._udp.local.\'" ']
            elif 'DNS' in protocol:
                info = protocol_list[-1].strip()
            # tcp/udp ['Ether ', ' IP ', ' UDP 192.168.31.253:54915 > 172.19.83.255:54915 ', ' Raw']
            elif 'TCP' in protocol or 'UDP' in protocol:
                info = ' '.join(protocol_list[2:]).strip()
            else:
                info = ' '.join(protocol_list[1:]).strip()
            return info
        else:
            return self.current_packet.summary()

    def get_src_and_dst(self):
        if self.current_packet.haslayer('IP'):
            src = self.current_packet['IP'].src
            dst = self.current_packet['IP'].dst
        else:
            src = self.current_packet[0].src
            dst = self.current_packet[0].dst
            if dst == 'ff:ff:ff:ff:ff:ff':
                dst = 'Broadcast'
        return src, dst

    def reassemble_packet(self, packet_list):
        # id = packet_list[0]['IP']['id(标识)']
        # for i in range(0, len(packet_list)):
        pass

    def handle(self, p: Packet):
        self.number += 1
        self.current_packet = p
        raw_data = p.show(dump=True)
        hex_info = scapy.utils.hexdump(p, dump=True)
        packet_time = str(p.time - self.time)[0:9]
        src, dst = self.get_src_and_dst()
        protocol = self.get_protocol()
        length = len(p)
        info = self.get_info(protocol)
        packet_info = PacketInfo(self.number, packet_time, src, dst, protocol, length, info, raw_data, hex_info)
        self.packets.append(packet_info)

        self.signals.update_table.emit(packet_info)

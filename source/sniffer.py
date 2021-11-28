from scapy.all import *
from PyQt5 import QtCore
from PyQt5.QtWidgets import *
import threading
import time
import signal


signals = signal.Signals()


class Sniffer:

    def __init__(self, _ui: QWidget):
        self.ui: QWidget = _ui
        self.nif = ''
        self.number = 0
        self.time = 0
        self.sniffer = None

    def start(self):
        self.nif = self.ui.if_box.currentText()
        if self.nif == '网卡':
            return
        print(self.nif)
        self.sniffer = AsyncSniffer(iface=self.nif, prn=self.handle)
        self.time = time.time()
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

    def handle(self, p: Packet):
        self.number += 1
        data = p.show(dump=True)
        # print(p['IP'].show(dump=True))
        # print(p.haslayer('IP'))
        # print(res)
        packet_time = p.time-self.time
        src = ''
        dst = ''
        if p.haslayer('IP'):
            src = p['IP'].src
            dst = p['IP'].dst
            print(src)
            print(dst)
        signals.update_table.emit([self.number, packet_time, src, dst, 'tmp', 'tmp', 'tmp'])



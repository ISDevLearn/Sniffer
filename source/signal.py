from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtGui import *
from packet import PacketInfo


class Signals(QObject):
    update_table = pyqtSignal(PacketInfo)

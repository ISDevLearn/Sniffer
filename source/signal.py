from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtGui import *


class Signals(QObject):
    update_table = pyqtSignal(list, QColor)

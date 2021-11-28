from PyQt5.QtCore import pyqtSignal, QObject


class Signals(QObject):
    update_table = pyqtSignal(list)

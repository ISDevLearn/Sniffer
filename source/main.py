from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
import sys
import utils


class Loader:
    def __init__(self):
        self.ui = uic.loadUi("main_window.ui")
        utils.modify(self.ui)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # 加载logo
    icon = QIcon('./img/logo.jpg')
    app.setWindowIcon(icon)

    # 显示窗口
    loader = Loader()
    loader.ui.showMaximized()
    sys.exit(app.exec_())

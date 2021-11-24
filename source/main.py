from PyQt5.QtWidgets import QApplication, QMainWindow
from mainwindow import Ui_MainWindow
import sys


class My_UI(QMainWindow, Ui_MainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # 显示窗口
    win = My_UI()
    win.show()
    sys.exit(app.exec_())

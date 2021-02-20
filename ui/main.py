import asyncio
import sys
import threading
import socket
import json
import time

from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class PromptDialog(QDialog):
    def __init__(self, question, parent=None):
        super().__init__(parent=parent)

        self.setWindowTitle("eBPFSnitch Dialog")

        message1 = QLabel("Application: " + question["executable"])
        message2 = QLabel("Destination Port: " + str(question["destinationPort"]))

        allowButton = QPushButton("Allow")
        denyButton = QPushButton("Deny")

        allowButton.clicked.connect(self.accept)
        denyButton.clicked.connect(self.reject)

        allowButton.setAutoDefault(False)
        denyButton.setAutoDefault(False)

        self.layout = QVBoxLayout()
        self.layout.addWidget(message1)
        self.layout.addWidget(message2)
        self.layout.addWidget(allowButton)
        self.layout.addWidget(denyButton)
        self.setLayout(self.layout)


class MainWindow(QMainWindow):
    _prompt_trigger = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()

        self.setWindowTitle("eBPFSnitch")

        button = QPushButton("does nothing button")
        button.clicked.connect(self.button_clicked)
        self.setCentralWidget(button)

        self._done = threading.Event()
        self._allow = False
        self._prompt_trigger.connect(self.on_prompt_trigger)

    def button_clicked(self):
        print("button click")

    @QtCore.pyqtSlot()
    def on_prompt_trigger(self):        
        dlg = PromptDialog(self._question)
        self._allow = bool(dlg.exec_())
        self._done.set()

    def handle_prompt(self, question):
        self._done.clear()
        self._question = question
        self._prompt_trigger.emit()
        self._done.wait()
        return self._allow

app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)

window = MainWindow()
# window.show()

icon = QIcon("icon.png")
tray = QSystemTrayIcon()
tray.setIcon(icon)
tray.setVisible(True)

menu = QMenu()
showMenuAction = QAction("show")
showMenuAction.triggered.connect(window.show)
menu.addAction(showMenuAction)

hideMenuAction = QAction("hide")
hideMenuAction.triggered.connect(window.hide)
menu.addAction(hideMenuAction)

quitMenuAction = QAction("Quit")
quitMenuAction.triggered.connect(app.quit)
menu.addAction(quitMenuAction)

tray.setContextMenu(menu)

async def daemon_client():
    reader, writer = await asyncio.open_unix_connection("/tmp/ebpfsnitch.sock")

    while True:
        line = await reader.readline()
        line = line.decode()
        print(line)
        parsed = json.loads(line)
        print(parsed["executable"])

        command = {
            "executable": parsed["executable"],
            "allow": window.handle_prompt(parsed)
        }

        serialized = str.encode(json.dumps(command) + "\n")

        writer.write(serialized)
        await writer.drain()

    print('Close the connection')
    writer.close()
    await writer.wait_closed()

loop = asyncio.get_event_loop()

def thread_function():
    print("start thread")
    try:
        loop.run_until_complete(daemon_client())
    except Exception as err:
        print("network error: " + repr(err))
    finally:
        loop.close()
    print("end thread")

networkThread = threading.Thread(target=thread_function)

networkThread.start()
app.exec_()
loop.call_soon_threadsafe(loop.stop)
networkThread.join()
import asyncio
import sys
import threading
import socket
import json
import time

from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt 

class PromptDialog(QDialog):
    def __init__(self, question, parent=None):
        super().__init__(parent=parent)

        self.setWindowTitle("eBPFSnitch Dialog")

        message1 = QLabel("Application: " + question["executable"])
        message2 = QLabel("Destination Address: " + question["destinationAddress"])
        message3 = QLabel("Destination Port: " + str(question["destinationPort"]))
        message4 = QLabel("Container " + str(question["container"]))

        allowButton = QPushButton("Allow")
        denyButton = QPushButton("Deny")

        self.forAllAddress = QCheckBox("All Destination Addresses")
        self.forAllPort = QCheckBox("All Destination Ports")

        allowButton.clicked.connect(self.accept)
        denyButton.clicked.connect(self.reject)

        allowButton.setAutoDefault(False)
        denyButton.setAutoDefault(False)

        self.layout = QVBoxLayout()
        self.layout.addWidget(message1)
        self.layout.addWidget(message2)
        self.layout.addWidget(message3)
        self.layout.addWidget(message4)
        self.layout.addWidget(self.forAllAddress)
        self.layout.addWidget(self.forAllPort)
        self.layout.addWidget(allowButton)
        self.layout.addWidget(denyButton)
        self.setLayout(self.layout)


class MainWindow(QMainWindow):
    _prompt_trigger = QtCore.pyqtSignal()
    _add_rule_trigger = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()

        self.setWindowTitle("eBPFSnitch")

        scroll = QScrollArea(self)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        scroll.setWidgetResizable(True)

        inner = QFrame(scroll)
        v = QVBoxLayout(scroll)
        v.setAlignment(Qt.AlignTop)
        v.addWidget(QLabel("Firewall Rules:"))
        inner.setLayout(v)

        scroll.setWidget(inner)

        self._rules = v

        self.setCentralWidget(scroll)

        self._done = threading.Event()
        self._allow = False

        self._prompt_trigger.connect(self.on_prompt_trigger)
        self._add_rule_trigger.connect(self.on_add_rule_trigger)

    def button_clicked(self):
        print("button click")

    @QtCore.pyqtSlot()
    def on_prompt_trigger(self):        
        dlg = PromptDialog(self._question)
        self._allow = bool(dlg.exec_())
        self._forAllAddress = dlg.forAllAddress.isChecked()
        self._forAllPort = dlg.forAllPort.isChecked()
        self._done.set()

    @QtCore.pyqtSlot()
    def on_add_rule_trigger(self):
        header = QHBoxLayout()
        header.addWidget(QLabel("Rule UUID: " + self._new_rule["ruleId"]))
        header.addWidget(QLabel("Allow: " + str(self._new_rule["allow"])))
        header.addWidget(QPushButton("Remove Rule"))
        header_widget = QWidget()
        header_widget.setLayout(header)

        body_widget = QTableWidget()
        body_widget.setColumnCount(2)
        body_widget.setRowCount(0)
        body_widget.resizeRowsToContents()
        body_widget.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        body_widget.verticalScrollBar().setDisabled(True);
        body_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body_widget.setHorizontalHeaderLabels(["Selector", "Matches"])
        body_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        for clause in self._new_rule["clauses"]:
            body_widget.insertRow(body_widget.rowCount())
            body_widget.setItem(body_widget.rowCount() - 1, 0, QTableWidgetItem(clause["field"]))
            body_widget.setItem(body_widget.rowCount() - 1, 1, QTableWidgetItem(clause["value"]))

        body_widget.setMaximumHeight(body_widget.rowHeight(0) * (body_widget.rowCount()) + body_widget.horizontalHeader().height())

        container = QVBoxLayout()
        container.setAlignment(Qt.AlignTop)
        container.addWidget(header_widget)
        container.addWidget(body_widget)

        item = QWidget()
        item.setLayout(container)
        item.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
    
        self._rules.addWidget(item)

    def handle_add_rule(self, rule):
        self._new_rule = rule
        self._add_rule_trigger.emit()

    def handle_prompt(self, question):
        self._done.clear()
        self._question = question
        self._prompt_trigger.emit()
        self._done.wait()
        return {
            "allow": self._allow,
            "forAllAddress": self._forAllAddress,
            "forAllPort": self._forAllPort
        }

app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)

window = MainWindow()
window.show()

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
    print("connected to daemon")

    while True:
        line = await reader.readuntil(separator=b'\n')
        line = line.decode()
        print(line)
    
        parsed = json.loads(line)

        if parsed["kind"] == "query":
            print(parsed["executable"])

            result = window.handle_prompt(parsed)

            command = {
                "allow": result["allow"],
                "clauses": [
                    {
                        "field": "executable",
                        "value": parsed["executable"]
                    }
                ]
            }

            if result["forAllAddress"] == False:
                command["clauses"].append(
                    {
                        "field": "destinationAddress",
                        "value": parsed["destinationAddress"]
                    }
                )

            if result["forAllPort"] == False:
                command["clauses"].append(
                    {
                        "field": "destinationPort",
                        "value": str(parsed["destinationPort"])
                    }
                )

            serialized = str.encode(json.dumps(command) + "\n")

            writer.write(serialized)
            await writer.drain()
        elif parsed["kind"] == "addRule":
            window.handle_add_rule(parsed["body"])
        else:
            print("unknown command")

    print('Close the connection')
    writer.close()
    await writer.wait_closed()

async def daemon_client_supervisor():
    while True:
        try:
            await daemon_client()
        except ConnectionRefusedError as err:
            print(repr(err))
        except asyncio.IncompleteReadError as err:
            print(repr(err))
        except FileNotFoundError as err:
            print(repr(err))

        print("retrying connection in one second")
        await asyncio.sleep(1)

loop = asyncio.get_event_loop()

def thread_function():
    print("start thread")
    try:
        loop.run_until_complete(daemon_client_supervisor())
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
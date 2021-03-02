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

# loop.call_soon_threadsafe(queue.put_nowait, time.time())
g_outbox = None
loop = asyncio.get_event_loop()

class PromptDialog(QDialog):
    def __init__(self, question, parent=None):
        super().__init__(parent=parent)

        self.setWindowTitle("eBPFSnitch Dialog")

        allowButton = QPushButton("Allow")
        denyButton = QPushButton("Deny")

        self.forAllDestinationAddresses = QCheckBox("All Destination Addresses")
        self.forAllDestinationPorts     = QCheckBox("All Destination Ports")
        self.forAllSourceAddresses      = QCheckBox("All Source Addresses")
        self.forAllSourcePorts          = QCheckBox("All Source Ports")
        self.forAllProtocols            = QCheckBox("All Protocols")
        self.forAllUIDs                 = QCheckBox("All UIDs")

        self.forAllSourcePorts.setChecked(True)

        allowButton.clicked.connect(self.accept)
        denyButton.clicked.connect(self.reject)

        allowButton.setAutoDefault(False)
        denyButton.setAutoDefault(False)

        source      = question["sourceAddress"]      + ":" + str(question["sourcePort"])
        destination = question["destinationAddress"] + ":" + str(question["destinationPort"])

        self.layout = QVBoxLayout()
        self.layout.addWidget(QLabel("Application: " + question["executable"]))
        self.layout.addWidget(QLabel("Protocol: " + str(question["protocol"])))
        self.layout.addWidget(QLabel("Source: " + source))
        self.layout.addWidget(QLabel("Destination: " + destination))
        self.layout.addWidget(QLabel("Container: " + str(question["container"])))
        self.layout.addWidget(QLabel("UID: "  + str(question["userId"])))
        self.layout.addWidget(self.forAllDestinationAddresses)
        self.layout.addWidget(self.forAllDestinationPorts)
        self.layout.addWidget(self.forAllSourceAddresses)
        self.layout.addWidget(self.forAllSourcePorts)
        self.layout.addWidget(self.forAllProtocols)
        self.layout.addWidget(self.forAllUIDs)
        self.layout.addWidget(allowButton)
        self.layout.addWidget(denyButton)
        self.setLayout(self.layout)

class MainWindow(QMainWindow):
    _prompt_trigger = QtCore.pyqtSignal()
    _add_rule_trigger = QtCore.pyqtSignal()
    _clear_rules_trigger = QtCore.pyqtSignal()

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
        self._clear_rules_trigger.connect(self.on_clear_rules_trigger)

    def button_clicked(self):
        print("button click")

    @QtCore.pyqtSlot()
    def on_prompt_trigger(self):        
        dlg = PromptDialog(self._question)
        allow = bool(dlg.exec_())
        self._verdict = {
            "allow":                      allow,
            "forAllDestinationAddresses": dlg.forAllDestinationAddresses.isChecked(),
            "forAllDestinationPorts":     dlg.forAllDestinationPorts.isChecked(),
            "forAllProtocols":            dlg.forAllProtocols.isChecked(),
            "forAllUIDs":                 dlg.forAllUIDs.isChecked(),
            "forAllSourceAddresses":      dlg.forAllSourceAddresses.isChecked(),
            "forAllSourcePorts":          dlg.forAllSourcePorts.isChecked(),
        }
        self._done.set()

    def on_delete_rule_trigger(self, ruleId, widget):
        print("clicked rule delete: " + ruleId);

        command = {
            "kind": "removeRule",
            "ruleId": ruleId
        }

        serialized = str.encode(json.dumps(command) + "\n")

        widget.deleteLater()

        loop.call_soon_threadsafe(g_outbox.put_nowait, serialized)

    @QtCore.pyqtSlot()
    def on_add_rule_trigger(self):
        ruleId = self._new_rule["ruleId"]
        delete_button = QPushButton("Remove Rule")

        header = QHBoxLayout()
        header.addWidget(QLabel("Rule UUID: " + self._new_rule["ruleId"]))
        header.addWidget(QLabel("Allow: " + str(self._new_rule["allow"])))
        header.addWidget(delete_button)
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

        delete_button.clicked.connect(lambda: self.on_delete_rule_trigger(ruleId, item))
    
        self._rules.addWidget(item)

        self._done.set()

    @QtCore.pyqtSlot()
    def on_clear_rules_trigger(self):
        print("clearing rules")

        for i in reversed(range(self._rules.count())): 
            self._rules.itemAt(i).widget().deleteLater()

        self._rules.addWidget(QLabel("Firewall Rules:"))

        self._done.set()

    def handle_add_rule(self, rule):
        self._done.clear()
        self._new_rule = rule
        self._add_rule_trigger.emit()
        self._done.wait()

    def handle_clear_rules(self):
        self._done.clear()
        self._clear_rules_trigger.emit()
        self._done.wait()

    def handle_prompt(self, question):
        self._done.clear()
        self._question = question
        self._prompt_trigger.emit()
        self._done.wait()
        return self._verdict

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

async def writer_task(writer, outbox):
    print("started writer_task")

    while True:
        item = await outbox.get()
        print("sending outbox item")
        writer.write(item)
        await writer.drain()
        outbox.task_done()

async def reader_task(reader, writer, outbox):
    print("started reader_task")

    while True:
        line = await reader.readuntil(separator=b'\n')
        line = line.decode()
        print(line)
    
        parsed = json.loads(line)

        if parsed["kind"] == "query":
            print(parsed["executable"])

            result = window.handle_prompt(parsed)

            command = {
                "kind": "addRule",
                "allow": result["allow"],
                "clauses": [
                    {
                        "field": "executable",
                        "value": parsed["executable"]
                    }
                ]
            }

            if result["forAllDestinationAddresses"] == False:
                command["clauses"].append(
                    {
                        "field": "destinationAddress",
                        "value": parsed["destinationAddress"]
                    }
                )

            if result["forAllDestinationPorts"] == False:
                command["clauses"].append(
                    {
                        "field": "destinationPort",
                        "value": str(parsed["destinationPort"])
                    }
                )

            if result["forAllSourceAddresses"] == False:
                command["clauses"].append(
                    {
                        "field": "sourceAddress",
                        "value": parsed["sourceAddress"]
                    }
                )

            if result["forAllSourcePorts"] == False:
                command["clauses"].append(
                    {
                        "field": "sourcePort",
                        "value": str(parsed["sourcePort"])
                    }
                )

            if result["forAllProtocols"] == False:
                command["clauses"].append(
                    {
                        "field": "protocol",
                        "value": parsed["protocol"]
                    }
                )

            if result["forAllUIDs"] == False:
                command["clauses"].append(
                    {
                        "field": "userId",
                        "value": str(parsed["userId"])
                    }
                )

            serialized = str.encode(json.dumps(command) + "\n")

            outbox.put_nowait(serialized)
        elif parsed["kind"] == "addRule":
            window.handle_add_rule(parsed["body"])
        elif parsed["kind"] == "setRules":
            window.handle_clear_rules()
            for rule in parsed["rules"]:
                print(rule)
                window.handle_add_rule(rule)
        else:
            print("unknown command")

async def daemon_client():
    reader, writer = await asyncio.open_unix_connection("/tmp/ebpfsnitch.sock")
    print("connected to daemon")

    outbox = asyncio.Queue()

    global g_outbox
    g_outbox = outbox

    await asyncio.wait([
        asyncio.create_task(writer_task(writer, outbox)),
        asyncio.create_task(reader_task(reader, writer, outbox))
    ])

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
        window.handle_clear_rules()
        print("retrying connection in one second")
        await asyncio.sleep(1)

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
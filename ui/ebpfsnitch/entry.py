#!/usr/bin/env python3

import socket
import sys
import select
import threading
import json
import queue
import time
import os

from PyQt5 import QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt

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
        self.persistent                 = QCheckBox("Persistent")
        self.priority                   = QSpinBox()

        self.forAllSourcePorts.setChecked(True)

        self.priority.setRange(0, 2147483647)
        self.priority.setValue(50)
        self.priority.setSingleStep(1)
        priorityLayout = QHBoxLayout()
        priorityLayout.addWidget(QLabel("Priority:"))
        priorityLayout.addWidget(self.priority)

        allowButton.clicked.connect(self.accept)
        denyButton.clicked.connect(self.reject)
        allowButton.setAutoDefault(False)
        denyButton.setAutoDefault(False)
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(allowButton)
        buttonLayout.addWidget(denyButton)

        source = question["sourceAddress"]      + ":" + str(question["sourcePort"])

        destination = \
            question["destinationAddress"] + ":" + \
            str(question["destinationPort"]) + \
            " (" + question["domain"] + ")"

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
        self.layout.addWidget(self.persistent)
        self.layout.addLayout(priorityLayout)
        self.layout.addLayout(buttonLayout)
        self.setLayout(self.layout)

class MainWindow(QMainWindow):
    _prompt_trigger = QtCore.pyqtSignal()
    _add_rule_trigger = QtCore.pyqtSignal()
    _clear_rules_trigger = QtCore.pyqtSignal()
    _show_rules_trigger = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()

        self.setWindowTitle("eBPFSnitch")
        self.resize(920, 600)

        self.scroll = QScrollArea(self)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll.setWidgetResizable(True)

        inner = QFrame(self.scroll)
        v = QVBoxLayout(self.scroll)
        v.setAlignment(Qt.AlignTop)
        v.addWidget(QLabel("Firewall Rules:"))
        inner.setLayout(v)

        self.scroll.setWidget(inner)

        self._rules = v

        disconnectedLabel = QLabel("Attempting to connect to daemon")
        disconnectedLabel.setAlignment(Qt.AlignCenter)

        self.stack = QStackedWidget(self)
        self.stack.addWidget(disconnectedLabel)
        self.stack.addWidget(self.scroll)

        self.setCentralWidget(self.stack)

        self._done = threading.Event()
        self._allow = False

        self._prompt_trigger.connect(self.on_prompt_trigger)
        self._add_rule_trigger.connect(self.on_add_rule_trigger)
        self._clear_rules_trigger.connect(self.on_clear_rules_trigger)
        self._show_rules_trigger.connect(self.on_show_rules_trigger)

    def set_daemon_client(self, client):
        self._client = client

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
            "priority":                   dlg.priority.value(),
            "persistent":                 dlg.persistent.isChecked()
        }
        self._done.set()

    def on_delete_rule_trigger(self, ruleId, widget):
        print("clicked rule delete: " + ruleId);

        command = {
            "kind": "removeRule",
            "ruleId": ruleId
        }

        self._client.send_dict(command)

        widget.deleteLater()

    @QtCore.pyqtSlot()
    def on_add_rule_trigger(self):
        ruleId = self._new_rule["ruleId"]
        delete_button = QPushButton("Remove Rule")

        header = QHBoxLayout()
        header.addWidget(QLabel("Rule UUID: " + self._new_rule["ruleId"]))
        header.addWidget(QLabel("Allow: " + str(self._new_rule["allow"])))
        header.addWidget(QLabel("Persistent: " + str(self._new_rule["persistent"])))
        header.addWidget(QLabel("Priority: " + str(self._new_rule["priority"])))
        header.addWidget(delete_button)
        header_widget = QWidget()
        header_widget.setLayout(header)

        body_widget = QTableWidget()
        body_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        body_widget.setSelectionMode(QAbstractItemView.NoSelection)
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

        self.stack.setCurrentIndex(0)

        for i in reversed(range(self._rules.count())): 
            self._rules.itemAt(i).widget().deleteLater()

        self._rules.addWidget(QLabel("Firewall Rules:"))

        self._done.set()

    @QtCore.pyqtSlot()
    def on_show_rules_trigger(self):
        self.stack.setCurrentIndex(1)

    def handle_add_rule(self, rule):
        self._done.clear()
        self._new_rule = rule
        self._add_rule_trigger.emit()
        self._done.wait()

    def handle_show_rules(self):
        self._show_rules_trigger.emit()

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

class DaemonClient:
    def __init__(self, address, window):
        self._address = address
        self._stopper = threading.Event()
        self._outbox = queue.Queue()
        self._window = window
        self._thread = threading.Thread(target=self.__run_supervisor)

    def start(self):
        self._thread.start()

    def __run_supervisor(self):
        while self._stopper.is_set() == False:
            try:
                self.__run()
            except Exception as err:
                print(repr(err))
                self._window.handle_clear_rules()
                self._stopper.wait(1)

    def __run(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._address)

        self.read_buffer = ""
        
        while self._stopper.is_set() == False:
            read_ready, _, _ = select.select([self.sock], [], [], 0.1)

            self.__handle_write()

            if read_ready:
                self.__handle_read()

    def __handle_read(self):
        msg = self.sock.recv(1024)

        if not msg:
            self.sock.close()
            raise

        self.read_buffer += msg.decode("utf-8")

        while True:
            lineEnd = self.read_buffer.find("\n")
            if lineEnd == -1:
                break
            line = self.read_buffer[:lineEnd]
            self.read_buffer = self.read_buffer[lineEnd+1:]
            self.__handle_line(line)

    def __handle_write(self):
        while self._outbox.qsize() > 0:
            item = self._outbox.get()
            self.sock.sendall(item)
            self._outbox.task_done()

    def __handle_line(self, line):
        parsed = json.loads(line)
        if parsed["kind"] == "query":
            print(parsed["executable"])

            result = self._window.handle_prompt(parsed)

            command = {
                "kind": "addRule",
                "allow": result["allow"],
                "priority": result["priority"],
                "persistent": result["persistent"],
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

            self.send_dict(command)
        elif parsed["kind"] == "addRule":
            self._window.handle_add_rule(parsed["body"])
        elif parsed["kind"] == "setRules":
            self._window.handle_clear_rules()
            for rule in parsed["rules"]:
                print(rule)
                self._window.handle_add_rule(rule)
            self._window.handle_show_rules()
        elif parsed["kind"] == "ping":
            ...
        else:
            print("unknown command")

    def stop(self):
        self._stopper.set()
        self._thread.join()

    def send_dict(self, message):
        self._outbox.put(str.encode(json.dumps(message) + "\n"))

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    window = MainWindow()
    window.show()

    icon = QIcon(os.path.dirname(os.path.abspath(__file__)) + "/ebpfsnitch.png")
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

    daemonClient = DaemonClient("/tmp/ebpfsnitch.sock", window)
    window.set_daemon_client(daemonClient)

    daemonClient.start()
    app.exec_()
    daemonClient.stop()

main()
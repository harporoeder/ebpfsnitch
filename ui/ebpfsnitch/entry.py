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

        source = question["sourceAddress"] + ":" + str(question["sourcePort"])

        destination = \
            question["destinationAddress"] + ":" + \
            str(question["destinationPort"])

        if "domain" in question:
            destination += " (" + question["domain"] + ")"

        self.layout = QVBoxLayout()
        self.layout.addWidget(QLabel("Application: " + question["executable"]))
        self.layout.addWidget(QLabel("Protocol: " + str(question["protocol"])))
        self.layout.addWidget(QLabel("Source: " + source))
        self.layout.addWidget(QLabel("Destination: " + destination))

        if "container" in question:
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
    _clear_state_trigger = QtCore.pyqtSignal()
    _show_state_trigger = QtCore.pyqtSignal()
    _new_event_trigger = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()

        self.setWindowTitle("eBPFSnitch")
        self.resize(920, 600)

        rulesScroll = self.__make_scroll()
        self._rules = rulesScroll.widget().layout()

        processesScroll = self.__make_scroll()
        self._processes = processesScroll.widget().layout()

        body_widget = QTableWidget()
        body_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        body_widget.setSelectionMode(QAbstractItemView.NoSelection)
        body_widget.setColumnCount(4)
        body_widget.setRowCount(0)
        body_widget.resizeRowsToContents()
        body_widget.verticalScrollBar().setDisabled(True);
        body_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body_widget.setHorizontalHeaderLabels(["Executable", "PID", "UID", "GID"])
        body_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        processesScroll.widget().layout().addWidget(body_widget)
        self._processes = body_widget

        self.tabs = QTabWidget()
        self.tabs.addTab(rulesScroll, "Firewall Rules")
        self.tabs.addTab(processesScroll, "Processes")

        disconnectedLabel = QLabel("Attempting to connect to daemon")
        disconnectedLabel.setAlignment(Qt.AlignCenter)

        self.stack = QStackedWidget(self)
        self.stack.addWidget(disconnectedLabel)
        self.stack.addWidget(self.tabs)

        self.setCentralWidget(self.stack)

        self._done = threading.Event()
        self._allow = False

        self._clear_state_trigger.connect(self.on_clear_state_trigger)
        self._show_state_trigger.connect(self.on_show_state_trigger)
        self._new_event_trigger.connect(self.on_new_event_trigger)

    def __make_scroll(self):
        scroll = QScrollArea(self)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        scroll.setWidgetResizable(True)
        inner = QFrame(scroll)
        layout = QVBoxLayout(scroll)
        layout.setAlignment(Qt.AlignTop)
        inner.setLayout(layout)
        scroll.setWidget(inner)
        return scroll

    def set_daemon_client(self, client):
        self._client = client

    def on_delete_rule_trigger(self, ruleId, widget):
        print("clicked rule delete: " + ruleId);

        command = {
            "kind": "removeRule",
            "ruleId": ruleId
        }

        self._client.send_dict(command)

        widget.deleteLater()

    def __add_process(self, event):
        self._processes.insertRow(self._processes.rowCount())
        self._processes.setItem(self._processes.rowCount() - 1, 0, QTableWidgetItem(event["executable"]))
        self._processes.setItem(self._processes.rowCount() - 1, 1, QTableWidgetItem(str(event["processId"])))
        self._processes.setItem(self._processes.rowCount() - 1, 2, QTableWidgetItem(str(event["userId"])))
        self._processes.setItem(self._processes.rowCount() - 1, 3, QTableWidgetItem(str(event["groupId"])))

    def __add_rule(self, event):
        ruleId = event["ruleId"]
        delete_button = QPushButton("Remove Rule")

        header = QHBoxLayout()
        header.addWidget(QLabel("Rule UUID: " + event["ruleId"]))
        header.addWidget(QLabel("Allow: " + str(event["allow"])))
        header.addWidget(QLabel("Persistent: " + str(event["persistent"])))
        header.addWidget(QLabel("Priority: " + str(event["priority"])))
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

        for clause in event["clauses"]:
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

    @QtCore.pyqtSlot()
    def on_new_event_trigger(self):
        event = self._new_event
        self._event_result = None

        if event["kind"] == "addProcess":
            self.__add_process(event)

        elif event["kind"] == "removeProcess":
            process = str(event["processId"])
            for row in range(self._processes.rowCount()):
                if self._processes.item(row, 1).text() == process:
                    self._processes.removeRow(row)
                    break
    
        elif event["kind"] == "setProcesses":
            for process in event["processes"]:
                self.__add_process(process)

        elif event["kind"] == "addRule":
            self.__add_rule(event["body"])

        elif event["kind"] == "setRules":
            for rule in event["rules"]:
                self.__add_rule(rule)
            self.on_show_state_trigger()

        elif event["kind"] == "query":
            parsed = event

            dlg = PromptDialog(event)

            command = {
                "kind": "addRule",
                "allow": bool(dlg.exec_()),
                "priority": dlg.priority.value(),
                "persistent": dlg.persistent.isChecked(),
                "clauses": [
                    {
                        "field": "executable",
                        "value": event["executable"]
                    }
                ]
            }

            if dlg.forAllDestinationAddresses.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "destinationAddress",
                        "value": parsed["destinationAddress"]
                    }
                )

            if dlg.forAllDestinationPorts.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "destinationPort",
                        "value": str(parsed["destinationPort"])
                    }
                )

            if dlg.forAllSourceAddresses.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "sourceAddress",
                        "value": parsed["sourceAddress"]
                    }
                )

            if dlg.forAllSourcePorts.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "sourcePort",
                        "value": str(parsed["sourcePort"])
                    }
                )

            if dlg.forAllProtocols.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "protocol",
                        "value": parsed["protocol"]
                    }
                )

            if dlg.forAllUIDs.isChecked() == False:
                command["clauses"].append(
                    {
                        "field": "userId",
                        "value": str(parsed["userId"])
                    }
                )

            self._event_result = command

        self._done.set()

    @QtCore.pyqtSlot()
    def on_clear_state_trigger(self):
        self.stack.setCurrentIndex(0)

        for i in reversed(range(self._rules.count())): 
            self._rules.itemAt(i).widget().deleteLater()

        self._processes.setRowCount(0)

        self._done.set()

    @QtCore.pyqtSlot()
    def on_show_state_trigger(self):
        self.stack.setCurrentIndex(1)

    def handle_show_state(self):
        self._show_state_trigger.emit()

    def handle_clear_state(self):
        self._done.clear()
        self._clear_state_trigger.emit()
        self._done.wait()

    def handle_event(self, process):
        self._done.clear()
        self._new_event = process
        self._new_event_trigger.emit()
        self._done.wait()
        return self._event_result

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
                self._window.handle_clear_state()
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
        command = self._window.handle_event(parsed)
        if command != None:
            self.send_dict(command)

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
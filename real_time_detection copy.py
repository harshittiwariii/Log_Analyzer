import sys
import threading
import time
import asyncio
import pyshark
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton, QListWidget, QWidget
from PyQt5.QtGui import QFont
import subprocess

# Set the event loop policy for Windows
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class RealTimeTrafficAnalyzer:
    def __init__(self):
        # Initialize Suricata subprocess
        self.suricata_process = subprocess.Popen(['suricata', '-c', '"E:\\suricata\\suricata.exe"', '-i', 'Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)', '-l', 'E:\\suricata\\log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.threats_detected = []

    def start_packet_capture(self):
        capture = pyshark.LiveCapture(interface='Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)', bpf_filter='tcp or udp')
        for packet in capture.sniff_continuously():
            self.analyze_packet(packet)

    def analyze_packet(self, packet):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer
        if self.detect_threat(packet):
            self.threats_detected.append(packet)

    def detect_threat(self, packet):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        # List of suspicious keywords
        suspicious_keywords = ['malware', 'attack', 'virus', 'hacker', 'exploit']

        # Check if any suspicious keyword is present in source or destination IP
        for keyword in suspicious_keywords:
            if keyword in src_ip or keyword in dst_ip:
                return True  # Threat detected

        return False  # No threat detected


class NetworkAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.real_time_analyzer = RealTimeTrafficAnalyzer()

        self.setWindowTitle("Real-Time Network Traffic Analyzer")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.lbl_status = QLabel("Status: Idle")
        self.lbl_status.setFont(QFont("Times", 16, QFont.Bold))
        layout.addWidget(self.lbl_status)

        self.btn_start = QPushButton("Start Capture")
        self.btn_start.setFont(QFont("Times", 12))
        self.btn_start.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 5px;")
        self.btn_start.clicked.connect(self.start_capture)
        layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("Stop Capture")
        self.btn_stop.setFont(QFont("Times", 12))
        self.btn_stop.setStyleSheet("background-color: #f44336; color: white; border-radius: 5px;")
        self.btn_stop.clicked.connect(self.stop_capture)
        layout.addWidget(self.btn_stop)

        self.list_threats = QListWidget()
        layout.addWidget(self.list_threats)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def start_capture(self):
        self.lbl_status.setText("Status: Capturing")
        threading.Thread(target=self.real_time_analyzer.start_packet_capture).start()

    def stop_capture(self):
        self.lbl_status.setText("Status: Idle")
        # Implement logic to stop packet capture

    def show_detected_threats(self):
        self.list_threats.clear()
        for threat in self.real_time_analyzer.threats_detected:
            self.list_threats.addItem(str(threat))

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NetworkAnalyzerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main( )

#!/usr/bin/env python3

from PyQt5.QtWidgets import QDialog, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import QSize
from scapy.utils import wrpcap, hexdump
import subprocess

class HexDumpDialog(QDialog):
	def __init__(self, ssid, pkt, parent=None):
		super().__init__(parent)

		self.setWindowTitle(f"HexDump Data for \"{ssid}\"")
		
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = xrandr_wxh.split('x')
		w = 700
		h = 410
		x = round((int(wh[0]) / 2) - (w / 2))
		y = round((int(wh[1]) / 2) - (h / 2))
		self.setGeometry(x, y, w, h)

		font = QFont("Courier")
		font.setStyleHint(QFont.TypeWriter)

		self.text_edit = QTextEdit(self)
		self.text_edit.setReadOnly(True)
		self.text_edit.setFont(font)
		hexdump_data = hexdump(pkt, dump=True)
		self.text_edit.setPlainText(hexdump_data)

		self.btn_save = QPushButton('Сохранить в pcap-файл')
		self.btn_save.setIcon(QIcon('icons/diskette.png'))
		self.btn_save.setIconSize(QSize(24, 24))
		self.btn_save.clicked.connect(self.save_pcap)
		
		self.pkt = pkt
		self.ssid = ssid
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_save)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.text_edit)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
	def save_pcap(self):
		options = QFileDialog.Options()
		file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", f"{self.ssid}.pcap", "PCAP Files (*.pcap)", options=options)
		
		if file_path:
			try:
				wrpcap(file_path, self.pkt)
			except Exception as e:
				print('Error')

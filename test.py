#!/usr/bin/env python3

from PyQt5.QtWidgets import QDialog, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QApplication
from PyQt5.QtGui import QFont, QIcon, QTextCursor
from PyQt5.QtCore import QSize
from scapy.utils import wrpcap, hexdump

import sys
import subprocess

class HexDumpDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.raw = \
		b"\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x99\x09\xa0\x00\xaf\x01" \
		b"\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x40\xed\x00\x62" \
		b"\x31\x74\x40\xed\x00\x62\x31\x74\x10\xa0\xc1\xf2\x99\x80\xbd\x0a" \
		b"\x00\x00\x64\x00\x31\x1c\x00\x0c\x54\x50\x2d\x4c\x69\x6e\x6b\x5f" \
		b"\x33\x31\x37\x34\x01\x08\x82\x84\x8b\x96\x12\x24\x48\x6c\x03\x01" \
		b"\x0a\x05\x04\x00\x01\x00\x00\x07\x06\x52\x55\x20\x01\x0d\x23\x20" \
		b"\x01\x00\x23\x02\x3f\x00\xc3\x02\x00\x7e\x46\x05\x72\x00\x01\x00" \
		b"\x00\x33\x0a\x0c\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x2a\x01\x00" \
		b"\x32\x04\x0c\x18\x30\x60\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00" \
		b"\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x31\x00\x50" \
		b"\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x47\x00\x10" \
		b"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x40\xed\x00\x62\x31\x74" \
		b"\x10\x3c\x00\x01\x03\x10\x49\x00\x06\x00\x37\x2a\x00\x01\x20\x2d" \
		b"\x1a\xef\x11\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
		b"\x00\x00\x00\x00\x00\x00\x18\x04\x87\x09\x00\x3d\x16\x0a\x00\x00" \
		b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
		b"\x00\x00\x00\x4a\x0e\x14\x00\x0a\x00\x2c\x01\xc8\x00\x14\x00\x05" \
		b"\x00\x19\x00\xbf\x0c\xb1\x79\xc9\x33\xfa\xff\x0c\x03\xfa\xff\x0c" \
		b"\x03\xc0\x05\x00\x00\x00\xfa\xff\x7f\x08\x01\x00\x08\x00\x00\x00" \
		b"\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00" \
		b"\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xdd\x07\x00\x0c" \
		b"\x43\x09\x00\x00\x00\xdd\x21\x00\x0c\xe7\x08\x00\x00\x00\xbf\x0c" \
		b"\xb1\x01\xc0\x33\x2a\xff\x92\x04\x2a\xff\x92\x04\xc0\x05\x00\x00" \
		b"\x00\x2a\xff\xc3\x03\x01\x02\x02"


		#self.setWindowTitle(f"HexDump Data for \"{ssid}\"")
		
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = xrandr_wxh.split('x')
		w = 850
		h = 510
		x = round((int(wh[0]) / 2) - (w / 2))
		y = round((int(wh[1]) / 2) - (h / 2))
		self.setGeometry(x, y, w, h)

		font = QFont("Courier", 14)
		font.setStyleHint(QFont.TypeWriter)

		self.text_editHex = QTextEdit(self)
		self.text_editHex.setReadOnly(True)
		self.text_editHex.setFont(font)
		self.text_editHex.setFixedWidth(600)
		self.text_editAscii = QTextEdit(self)
		self.text_editAscii.setReadOnly(True)
		self.text_editAscii.setFont(font)
		
		scroll1 = self.text_editHex.verticalScrollBar()
		scroll2 = self.text_editAscii.verticalScrollBar()
		
		self.text_editAscii.cursorPositionChanged.connect(self.ascii_editor_select)
		
		scroll1.valueChanged.connect(
			scroll2.setValue
		)
		scroll2.valueChanged.connect(
			scroll1.setValue
		)
		
		i = 0
		for byte in self.raw:
			self.text_editHex.insertPlainText(f'{byte:02x} ')
			if ((i + 1) % 8 == 0):
				self.text_editHex.insertPlainText(" ")
			if ((i + 1) % 16 == 0):
				self.text_editHex.insertPlainText("\n")
			i += 1
			
		i = 0
		for byte in self.raw:
			char = chr(byte)
			if byte >= 32 and byte <= 126:
				self.text_editAscii.insertPlainText(chr(byte))
			else:
				self.text_editAscii.insertPlainText('.')

			if ((i + 1) % 16 == 0):
				self.text_editAscii.insertPlainText("\n")
			i += 1
			
		scroll1.setValue(0)
		scroll2.setValue(0)

		self.btn_save = QPushButton('Сохранить в pcap-файл')
		self.btn_save.setIcon(QIcon('icons/diskette.png'))
		self.btn_save.setIconSize(QSize(24, 24))
		self.btn_save.clicked.connect(self.save_pcap)
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_save)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()
		
		textedit_layout = QHBoxLayout()
		textedit_layout.addWidget(self.text_editHex)
		textedit_layout.addWidget(self.text_editAscii)
		
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(textedit_layout)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
	
	def ascii_editor_select(self):
		cursor = self.text_editAscii.textCursor() 
		print(cursor.position())
		
	def save_pcap(self):
		options = QFileDialog.Options()
		file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", f"{self.ssid}.pcap", "PCAP Files (*.pcap)", options=options)
		
		if file_path:
			try:
				wrpcap(file_path, self.pkt)
			except Exception as e:
				print('Error')

if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = HexDumpDialog()
	window.show()
	sys.exit(app.exec_())

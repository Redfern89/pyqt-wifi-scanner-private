#!/usr/bin/env python3

from PyQt5.QtWidgets import QDialog, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QApplication
from PyQt5.QtGui import QFont, QIcon, QTextCursor, QPalette, QColor
from PyQt5.QtCore import Qt, QSize
from scapy.utils import wrpcap, hexdump

import sys
import subprocess

class HexDumpDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.raw_data = \
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

		# Get screen resolution and position window at center
		screen_resolution = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		screen_width, screen_height = map(int, screen_resolution.split('x'))
		window_width, window_height = 900, 510
		x_pos = (screen_width // 2) - (window_width // 2)
		y_pos = (screen_height // 2) - (window_height // 2)
		self.setGeometry(x_pos, y_pos, window_width, window_height)

		# Set font for text areas
		font = QFont("Courier", 14)
		font.setStyleHint(QFont.TypeWriter)

		# Initialize text areas
		self.position_text_edit = QTextEdit(self)
		self.position_text_edit.setReadOnly(True)
		self.position_text_edit.setFont(font)
		self.position_text_edit.setFixedWidth(80)
		palette = self.position_text_edit.palette()
		palette.setColor(QPalette.Base, QColor("#f2f2f2"))
		self.position_text_edit.setPalette(palette)

		self.hex_text_edit = QTextEdit(self)
		self.hex_text_edit.setReadOnly(True)
		self.hex_text_edit.setFont(font)
		self.hex_text_edit.setFixedWidth(600)

		self.ascii_text_edit = QTextEdit(self)
		self.ascii_text_edit.setReadOnly(True)
		self.ascii_text_edit.setFont(font)
		self.manual_cursor_update = False

		# Connect scroll bars to synchronize scrolling
		scroll_pos = self.position_text_edit.verticalScrollBar()
		scroll_hex = self.hex_text_edit.verticalScrollBar()
		scroll_ascii = self.ascii_text_edit.verticalScrollBar()

		self.ascii_text_edit.cursorPositionChanged.connect(self.sync_ascii_hex_cursor_position)
		self.hex_text_edit.cursorPositionChanged.connect(self.sync_hex_ascii_cursor_position)
		#self.hex_text_edit.selectionChanged.connect(self.sync_hex_ascii_cursor_position)


		scroll_pos.valueChanged.connect(scroll_hex.setValue)
		scroll_pos.valueChanged.connect(scroll_ascii.setValue)
		scroll_hex.valueChanged.connect(scroll_pos.setValue)
		scroll_hex.valueChanged.connect(scroll_ascii.setValue)
		scroll_ascii.valueChanged.connect(scroll_pos.setValue)
		scroll_ascii.valueChanged.connect(scroll_hex.setValue)

		# Insert raw data into hex, position, and ascii text areas
		self.insert_raw_data()

		# Create save button
		self.save_button = QPushButton('Save to pcap file')
		self.save_button.setIcon(QIcon('icons/diskette.png'))
		self.save_button.setIconSize(QSize(24, 24))
		self.save_button.clicked.connect(self.save_pcap)

		# Layout setup
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.save_button)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		textedit_layout = QHBoxLayout()
		textedit_layout.addWidget(self.position_text_edit)
		textedit_layout.addWidget(self.hex_text_edit)
		textedit_layout.addWidget(self.ascii_text_edit)

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(textedit_layout)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)

	def insert_raw_data(self):
		# Fill hex, position and ascii text areas with raw data
		byte_blocks = [list(self.raw_data[i:i + 16]) for i in range(0, len(self.raw_data), 16)]
		
		for line, block in enumerate(byte_blocks):
			self.hex_text_edit.append(' '.join(f'{b:02x}' for b in block))
			self.ascii_text_edit.append(''.join(chr(b) if 32 <= b <= 126 else '.' for b in block))
			self.position_text_edit.append(f'{line:04x}')

	def sync_ascii_hex_cursor_position(self):
		cursor_ascii = self.ascii_text_edit.textCursor()
		cursor_hex = self.hex_text_edit.textCursor()

		hex_text = self.hex_text_edit.toPlainText()
		hex_text_length = len(hex_text)

		selection_start = cursor_ascii.selectionStart()
		selection_end = cursor_ascii.selectionEnd()

		def ascii_to_hex_offset(ascii_offset):
			hex_offset = 0
			ascii_index = 0

			while ascii_index < ascii_offset and hex_offset < hex_text_length:
				print(f"hex_offset: {hex_offset}, ascii_index: {ascii_index}, char: '{hex_text[hex_offset]}'")

				# Пропускаем \n, но НЕ увеличиваем ascii_index
				if hex_text[hex_offset] == '\n':
					print("New line detected! Skipping without ascii_index increment.")
					hex_offset += 1
					continue

				# Двигаемся на два символа HEX
				hex_offset += 2  
				ascii_index += 1  

				# Проверяем, есть ли пробел (если не конец строки)
				if hex_offset < hex_text_length and hex_text[hex_offset] not in ('\n', ' '):
					continue  

				# Если пробел есть - учитываем его
				if hex_offset < hex_text_length and hex_text[hex_offset] == ' ':
					hex_offset += 1  

			return hex_offset


		hex_start = ascii_to_hex_offset(selection_start)
		hex_end = ascii_to_hex_offset(selection_end)

		print(f"ASCII: {selection_start} -> HEX: {hex_start}")
		print(f"ASCII: {selection_end} -> HEX: {hex_end}")

		cursor_hex.setPosition(hex_start)
		cursor_hex.setPosition(hex_end, QTextCursor.KeepAnchor)

		self.hex_text_edit.setTextCursor(cursor_hex)
		self.hex_text_edit.ensureCursorVisible()
   

	def sync_hex_ascii_cursor_position(self):
		if QApplication.focusWidget() is self.hex_text_edit:
			cursor_hex = self.hex_text_edit.textCursor()
			text = self.hex_text_edit.toPlainText()

			# Если есть выделение
			
			if cursor_hex.hasSelection():
				selection_start = cursor_hex.selectionStart()
				selection_end = cursor_hex.selectionEnd()

				# Корректируем на границы байтов
				if selection_start % 3 != 0:
					selection_start -= selection_start % 3  # Начало байта
				if selection_end % 3 != 2:
					selection_end += 2 - selection_end % 3  # Конец байта

				# Ограничиваем выделение внутри текста
				selection_start = max(0, selection_start)
				selection_end = min(len(text), selection_end)

				# Явная проверка направления выделения
				if selection_start < selection_end:
					# Позиции инвертированы (снизу вверх), мы меняем их местами
					selection_start, selection_end = selection_end, selection_start

				# Устанавливаем новый курсор с выделением
				cursor_hex.setPosition(selection_start)
				cursor_hex.setPosition(selection_end, QTextCursor.KeepAnchor)
				self.hex_text_edit.setTextCursor(cursor_hex)

		# Если нет выделения, выделяем один байт
		#else:
		
		'''
		pos = cursor_hex.position()
		sel = pos % 3

		if sel == 0:
			start_sel, end_sel = pos, pos + 2  # Начало и конец байта
		elif sel == 1:
			start_sel, end_sel = pos - 1, pos + 1  # Выделяем целый байт
		else:
			start_sel, end_sel = pos - 2, pos  # Выделяем целый байт

		# Ограничиваем start и end, чтобы не выйти за пределы текста
		start_sel = max(0, start_sel)
		end_sel = min(len(text), end_sel)

		# Устанавливаем новый курсор с выделением
		cursor_hex.setPosition(start_sel)
		cursor_hex.setPosition(end_sel, QTextCursor.KeepAnchor)
		self.hex_text_edit.setTextCursor(cursor_hex)
		pass
		'''




	def save_pcap(self):
		options = QFileDialog.Options()
		file_path, _ = QFileDialog.getSaveFileName(self, "Save as", "output.pcap", "PCAP Files (*.pcap)", options=options)


if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = HexDumpDialog()
	window.show()
	sys.exit(app.exec_())

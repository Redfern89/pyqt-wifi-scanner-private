#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QDialog, QPushButton, QVBoxLayout, QHBoxLayout, QApplication, QTableView, QStyledItemDelegate
)
from PyQt5.QtGui import QFont, QIcon, QColor, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, QSize, QItemSelection, QItemSelectionModel
import sys
import subprocess


class CenterDelegate(QStyledItemDelegate):
	def paint(self, painter, option, index):
		if index.column() > 0:
			option.displayAlignment = Qt.AlignCenter
		super().paint(painter, option, index)


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
		
		
		self.init_ui()
		self.insert_raw_data()
		self.parse_packets()
		
	def parse_packets(self):
		rt_len = self.raw_data[2]
		self.highlight_items(0, rt_len)
		frame_type = self.raw_data[rt_len:rt_len+2]
		
		if frame_type == b'\x80\x00':
			mac_offset = rt_len + 4
			addr1 = self.raw_data[mac_offset:mac_offset+6]
			self.highlight_items(mac_offset, 6, "#85aff2", "white")
			self.highlight_items(mac_offset +6, 6, "#2f7cf7", "white")
			self.highlight_items(mac_offset +12, 6, "#9ea5b0", "white")

			tagged_offset = mac_offset + 32
			remaining_length = len(self.raw_data) - tagged_offset
			self.highlight_items(tagged_offset, remaining_length)
			print(self.raw_data[tagged_offset:remaining_length])
			

	def init_ui(self):
		self.setGeometry(*self.center_window(1000, 510))
		font = QFont("Courier", 14, QFont.TypeWriter)

		self.save_button = QPushButton('Save to pcap file')
		self.save_button.setIcon(QIcon('icons/diskette.png'))
		self.save_button.setIconSize(QSize(24, 24))

		self.hex_table_model, self.hex_table = self.create_table(font)
		self.ascii_table_model, self.ascii_table = self.create_table(font, fixed_width=260)

		self.hex_table.selectionModel().selectionChanged.connect(self.sync_selection_hex_ascii)
		self.ascii_table.selectionModel().selectionChanged.connect(self.sync_selection_ascii_hex)
		
		self.hex_table.horizontalHeader().setVisible(True)
		self.hex_table.verticalHeader().setVisible(True)

		header_items = []
		#header_items.append('H')
		for i in range(16):
			header_items.append(f'{i:02X}')
		
		self.hex_table_model.setHorizontalHeaderLabels(header_items)

		top_layout = QHBoxLayout()
		top_layout.addWidget(self.save_button)
		top_layout.addStretch()

		text_layout = QHBoxLayout()
		text_layout.addWidget(self.hex_table)
		text_layout.addWidget(self.ascii_table)

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(text_layout)
		self.setLayout(main_layout)
		self.sync_scrolls()

	def create_table(self, font, fixed_width=None):
		model = QStandardItemModel()
		table = QTableView()
		table.setModel(model)
		table.setShowGrid(False)
		table.setEditTriggers(QTableView.NoEditTriggers)
		table.verticalHeader().setVisible(False)
		table.horizontalHeader().setVisible(False)
		table.setItemDelegate(CenterDelegate(table))
		table.setSelectionMode(QTableView.ExtendedSelection)
		table.setSelectionBehavior(QTableView.SelectItems)
		table.setFont(font)
		if fixed_width:
			table.setFixedWidth(fixed_width)
		return model, table

	def center_window(self, width, height):
		screen = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode().strip()
		screen_width, screen_height = map(int, screen.split('x'))
		x, y = (screen_width - width) // 2, (screen_height - height) // 2
		return x, y, width, height

	def insert_raw_data(self):
		byte_blocks = [self.raw_data[i:i + 16] for i in range(0, len(self.raw_data), 16)]
		pos_items = []

		for line, block in enumerate(byte_blocks):
			bg_color = QColor('#f5fbff') if line % 2 == 0 else QColor('#ffffff')

			pos_items.append(f'{line:04X}')
			hex_items = []
			ascii_items = []

			for idx, byte in enumerate(block):
				hex_item = QStandardItem(f'{byte:02X}')
				hex_item.setBackground(bg_color)
				hex_item.setForeground(QColor('#8c8c8c') if byte == 0x00 else QColor('#000000'))
				hex_item.setData(line * 16 + idx, Qt.UserRole)
				hex_items.append(hex_item)

				ascii_items.append(QStandardItem(chr(byte) if 32 <= byte <= 126 else '.'))

			self.hex_table_model.appendRow(hex_items)
			self.hex_table_model.setVerticalHeaderLabels(pos_items)
			self.ascii_table_model.appendRow(ascii_items)

		self.adjust_column_widths()

	def adjust_column_widths(self):
		for col in range(self.ascii_table_model.columnCount()):
			self.ascii_table.setColumnWidth(col, 10)
		for col in range(self.hex_table_model.columnCount()):
			self.hex_table.setColumnWidth(col, 35)
			

	def highlight_items(self, offset, count, bg="yellow", fg="black"):
		for row in range(self.hex_table_model.rowCount()):
			for col in range(self.hex_table_model.columnCount()):
				hex_index = self.hex_table_model.index(row, col)
				hex_item = self.hex_table_model.itemFromIndex(hex_index)
				
				ascii_index = self.ascii_table_model.index(row, col)
				ascii_item = self.ascii_table_model.itemFromIndex(ascii_index)
				
				cell_index = hex_item.data(Qt.UserRole)
				if not cell_index is None:
					if offset <= cell_index < offset + count:
						hex_item.setBackground(QColor(bg))
						hex_item.setForeground(QColor(fg))
						if not ascii_item is None:
							ascii_item.setBackground(QColor(bg))
							ascii_item.setForeground(QColor(fg))

	def sync_selection_hex_ascii(self, selected, _):
		if QApplication.focusWidget() is not self.hex_table:
			return
			
		hex_selection_model = self.hex_table.selectionModel()
		ascii_selection_model = self.ascii_table.selectionModel()
		ascii_selection_model.clearSelection()
		for idx in hex_selection_model.selectedIndexes():
			ascii_index = self.ascii_table_model.index(idx.row(), idx.column())
			ascii_selection_model.select(ascii_index, QItemSelectionModel.Select)
			
	def sync_selection_ascii_hex(self, selected, _):
		if QApplication.focusWidget() is not self.ascii_table:
			return
		hex_selection_model = self.hex_table.selectionModel()
		ascii_selection_model = self.ascii_table.selectionModel()
		hex_selection_model.clearSelection()
		for idx in ascii_selection_model.selectedIndexes():
			hex_index = self.hex_table_model.index(idx.row(), idx.column())
			hex_selection_model.select(hex_index, QItemSelectionModel.Select)
			
	def sync_scrolls(self):
		scroll0 = self.hex_table.verticalScrollBar()
		scroll1 = self.ascii_table.verticalScrollBar()
		scroll0.valueChanged.connect(scroll1.setValue)
		scroll1.valueChanged.connect(scroll0.setValue)


if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = HexDumpDialog()
	window.show()
	sys.exit(app.exec_())

#!/usr/bin/env python3

from PyQt5.QtWidgets import QDialog, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QApplication, QTableView, QStyledItemDelegate
from PyQt5.QtGui import QFont, QIcon, QTextCursor, QPalette, QColor, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, QSize, QModelIndex, QAbstractTableModel, QItemSelection, QItemSelectionModel, QEvent
from scapy.utils import wrpcap, hexdump

import sys
import subprocess

class CenterDelegate(QStyledItemDelegate):
	def paint(self, painter, option, index):
		if index.column() > 0:
			option.displayAlignment = Qt.AlignmentFlag.AlignCenter
			super().paint(painter, option, index)
		else:
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

		# Get screen resolution and position window at center
		screen_resolution = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		screen_width, screen_height = map(int, screen_resolution.split('x'))
		window_width, window_height = 1000, 510
		x_pos = (screen_width // 2) - (window_width // 2)
		y_pos = (screen_height // 2) - (window_height // 2)
		self.setGeometry(x_pos, y_pos, window_width, window_height)

		# Set font for text areas
		font = QFont("Courier", 14)
		font.setStyleHint(QFont.TypeWriter)

		self.save_button = QPushButton('Save to pcap file')
		self.save_button.setIcon(QIcon('icons/diskette.png'))
		self.save_button.setIconSize(QSize(24, 24))

		top_layout = QHBoxLayout()
		top_layout.addWidget(self.save_button)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		self.hex_table_model = QStandardItemModel()
		self.hex_table = QTableView()
		self.hex_table.setModel(self.hex_table_model)
		self.hex_table.setShowGrid(False)
		self.hex_table.setEditTriggers(QTableView.NoEditTriggers)
		self.hex_table.verticalHeader().setVisible(False)
		self.hex_table.horizontalHeader().setVisible(False)
		self.hex_table.setItemDelegate(CenterDelegate(self.hex_table))
		self.hex_table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
		self.hex_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)  # Выделяем отдельные ячейки
		self.hex_table.selectionModel().selectionChanged.connect(self.hex_table_selection_sync)
		self.hex_table.installEventFilter(self)
		self.hex_table.setFont(font)

		self.ascii_table_model = QStandardItemModel()
		self.ascii_table = QTableView()
		self.ascii_table.setModel(self.ascii_table_model)
		self.ascii_table.setShowGrid(False)
		self.ascii_table.setEditTriggers(QTableView.NoEditTriggers)
		self.ascii_table.verticalHeader().setVisible(False)
		self.ascii_table.horizontalHeader().setVisible(False)
		self.ascii_table.setItemDelegate(CenterDelegate(self.hex_table))
		self.ascii_table.setFont(font)
		self.ascii_table.setFixedWidth(260)

		textedit_layout = QHBoxLayout()
		textedit_layout.addWidget(self.hex_table)
		textedit_layout.addWidget(self.ascii_table)

		main_layout = QVBoxLayout()	
		main_layout.addLayout(top_layout)
		main_layout.addLayout(textedit_layout)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)

		self.insert_raw_data()

		for col in range(self.ascii_table.model().columnCount()):
			self.ascii_table.setColumnWidth(col, 10)

		for col in range(self.hex_table.model().columnCount()):
			if col == 0:
				self.hex_table.setColumnWidth(0, 60)
			else:
				self.hex_table.setColumnWidth(col, 35)
			#self.hex_table.setFixedWidth(10)

	def hex_table_selection_sync(self, selected: QItemSelection, deselected: QItemSelection):
		hex_selection_model = self.hex_table.selectionModel()
		ascii_selection_model = self.ascii_table.selectionModel()

		# Получаем индексы выделенных ячеек
		hex_indexes = hex_selection_model.selectedIndexes()

		for idx in hex_indexes:
			if idx.column() == 0:  # Если это 0-я колонка
				# Снимаем выделение с этой ячейки
				hex_selection_model.select(idx, QItemSelectionModel.Deselect)
				ascii_selection_model.select(idx, QItemSelectionModel.Deselect)
		# Создаём новое выделение для ASCII-таблицы
		ascii_selection = QItemSelection()

		for idx in hex_indexes:
			ascii_index = self.ascii_table.model().index(idx.row(), idx.column() -1)
			ascii_selection.merge(QItemSelection(ascii_index, ascii_index), QItemSelectionModel.Select)

		# Отключаем сигналы, чтобы не зациклить обновления
		try:
			ascii_selection_model.selectionChanged.disconnect(self.hex_table_selection_sync)
		except TypeError:
			pass  # Если сигнал не был подключён, то просто пропускаем

		# Применяем выделение в ASCII-таблице
		ascii_selection_model.clearSelection()
		ascii_selection_model.select(ascii_selection, QItemSelectionModel.Select)

		# Включаем сигналы обратно
		#ascii_selection_model.selectionChanged.connect(self.hex_table_selection_sync)

	def highlight_items(self, offset, count):
		for row in range(self.hex_table_model.rowCount()):
			for col in range(self.hex_table_model.columnCount()):
				index = self.hex_table_model.index(row, col)
				item = self.hex_table_model.itemFromIndex(index)
				cell_index = item.data(Qt.UserRole)
				if cell_index:
					print(cell_index)
					if offset <= cell_index < offset + count:
						#print(cell_index)
						item.setBackground(QColor("yellow"))
			

	def insert_raw_data(self):
		# Fill hex, position and ascii text areas with raw data
		rt_len = self.raw_data[2]
		byte_blocks = [list(self.raw_data[i:i + 16]) for i in range(0, len(self.raw_data), 16)]
		
		idx = 0
		for line, block in enumerate(byte_blocks):
			hex_items = []
			ascii_items = []
			pos_item = QStandardItem(f'{line:04X}')
			hex_items.append(pos_item)
			pos_item.setBackground(QColor('#f0f0f0'))
			for byte_idx, byte in enumerate(block):
				if line % 2 == 0:
					bg = QColor('#f5fbff')
				else:
					bg = QColor('#ffffff')

				if byte == 0x00:
					fg = QColor('#8c8c8c')
				else:
					fg = QColor('#000000')
				hex_item = QStandardItem(f'{byte:02X}')
				hex_item.setBackground(bg)
				hex_item.setForeground(fg)
				hex_item.setData(int(idx), Qt.UserRole)			

				hex_items.append(hex_item)

				if byte >= 26 and byte <= 126:
					char = chr(byte)
				else:
					char = '.'
				ascii_item = QStandardItem(char)
				ascii_item.setForeground(fg)
				ascii_items.append(ascii_item)
				idx += 1

			self.hex_table_model.appendRow(hex_items)
			self.ascii_table_model.appendRow(ascii_items)

			#idx += 1

			self.highlight_items(0, 4)


if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = HexDumpDialog()
	window.show()
	sys.exit(app.exec_())

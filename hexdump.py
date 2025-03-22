#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QDialog, QPushButton, QVBoxLayout, QHBoxLayout, QApplication, QTableView, QStyledItemDelegate
)
from PyQt5.QtGui import QFont, QIcon, QColor, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, QSize, QItemSelection, QItemSelectionModel, QRect
from misc import Utils
import sys
import subprocess

from scapy.all import RadioTap, Dot11, Dot11Elt, Dot11Beacon

class HexAsciiTableDeligate(QStyledItemDelegate):
	def paint(self, painter, option, index):
		if index.column() > 0:
			option.displayAlignment = Qt.AlignCenter
		super().paint(painter, option, index)


class HexDumpDialog(QDialog):
	def __init__(self, ssid, pkt, parent=None):
		super().__init__(parent)

		self.raw_data = bytes(pkt)
		self.ssid = ssid

		self.init_ui()
		self.insert_raw_data()

	def init_ui(self):
		self.setWindowTitle(f"HexDump Data for \"{self.ssid}\"")
		self.setGeometry(*self.center_window(1000, 500))
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
#		self.hex_table.selectionModel().selectionChanged.connect(self.on_hex_selection_changed)

		self.hex_table.setItemDelegate(HexAsciiTableDeligate(self.hex_table))

		header_items = []
		for i in range(16):
			header_items.append(f'{i:02X}')
		
		self.hex_table_model.setHorizontalHeaderLabels(header_items)

		top_layout = QHBoxLayout()
		top_layout.addWidget(self.save_button)
		top_layout.addStretch()

		text_layout = QHBoxLayout()
		top_layout.setContentsMargins(5, 10, 5, 0)
		text_layout.addWidget(self.hex_table)
		text_layout.addWidget(self.ascii_table)

		main_layout = QVBoxLayout()
		main_layout.setContentsMargins(0, 0, 0, 0)
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
		#table.setItemDelegate(HexAsciiTableDeligate(table))
		table.setSelectionMode(QTableView.ExtendedSelection)
		table.setSelectionBehavior(QTableView.SelectItems)
		table.setFont(font)
		if fixed_width:
			table.setFixedWidth(fixed_width)
		return model, table

	def _get_selected_row(self):
		indexes = self.hex_table.selectionModel().selectedIndexes()
		return indexes[0].row() if indexes else None
	
	def _get_selected_col(self):
		indexes = self.hex_table.selectionModel().selectedIndexes()
		return indexes[0].column() if indexes else None
	
	def _get_selected_row_col(self):
		return self._get_selected_row(), self._get_selected_col()

	def _get_value(self, row, column, role=Qt.DisplayRole):
		return self.hex_table_model.data(self.hex_table_model.index(row, column), role)

#	def on_hex_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
#		row = self._get_selected_row()
#		col = self._get_selected_col()
#		offset_val = self._get_value(row, col, Qt.UserRole +1)
#
#		for row in range(self.hex_table_model.rowCount()):
#			for col in range(self.hex_table_model.columnCount()):
#				current_offset_val = self._get_value(row, col, Qt.UserRole +1)
#				if current_offset_val == offset_val:


		#print(self._get_value(row, col, Qt.UserRole +2))

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
		row_cols = []
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

'''
if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = HexDumpDialog()
	window.show()
	sys.exit(app.exec_())
'''
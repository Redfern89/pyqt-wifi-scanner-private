#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QGroupBox, QFrame, QSpinBox
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QColor, QPen, QPainterPath, QFont
from PyQt5.QtCore import Qt, QSize, QTimer

import sys

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
    return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class ProgressBarDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		if 1:
			try:
				rssi_value = int(index.data())
			except ValueError:
				return
		
			signal_strength = int(scale_rssi(rssi_value, -85, -40, 0, 100))
			padding = 6
			bar_rect = option.rect.adjusted(padding, padding, -padding, -padding)

			if option.state & QStyle.State_Selected:
				painter.fillRect(option.rect, option.palette.highlight())

			progress_option = QStyleOptionProgressBar()
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None

class DeauthDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)
		
		self.deauth_reasons = {
			1: "Unspecified reason",
			2: "Previous authentication no longer valid",
			3: "Deauthenticated because sending station is leaving (or has left) IBSS or ESS",
			4: "Disassociated due to inactivity",
			5: "Disassociated because AP is unable to handle all currently associated stations",
			6: "Class 2 frame received from nonauthenticated station",
			7: "Class 3 frame received from nonassociated station",
			8: "Disassociated because sending station is leaving (or has left) BSS",
			9: "Station requesting (re)association is not authenticated with responding station",
			34: "Deauthenticated because of 802.1X authentication failed"
		}

		self.setWindowTitle(f"Мониторинг сети ya_setko")
		self.setGeometry(200, 200, 1200, 560)
		
		self.bssid_label = QLabel("<b>BSSID:</b> 04:5E:CD:1F:66:BE")
		self.ch_label = QLabel("<b>Channel:</b> 11")
		self.ssid_label = QLabel("<b>SSID:</b> ya_setko")
		self.beacons_label = QLabel("<b>Beacons:</b> 761")
		
		self.pb_layout = QHBoxLayout()
		
		self.rssi_pb = QProgressBar()		
		self.rssi_pb.setMinimum(0)
		self.rssi_pb.setMaximum(100)
		self.rssi_pb.setValue(73)
		self.rssi_pb.setFormat("-73 dBm")
		
		self.pb_layout.addWidget(QLabel('<b>RSSI: </b>'))
		self.pb_layout.addWidget(self.rssi_pb)
		
		status_layout = QVBoxLayout()
		status_layout.setContentsMargins(5, 5, 5, 0)	
		status_layout.addWidget(self.ssid_label)
		status_layout.addWidget(self.ch_label)
		status_layout.addWidget(self.bssid_label)
		status_layout.addWidget(self.beacons_label)
		status_layout.addLayout(self.pb_layout)
		status_layout.setContentsMargins(5, 5, 5, 5)
		
		settings_layout = QVBoxLayout()
		settings_layout.setContentsMargins(5, 5, 5, 5)
		
		self.deauth_packets_edit = QSpinBox()
		self.deauth_packets_edit.setRange(1, 100)
		self.deauth_packets_edit.setValue(10)
		deauth_packets_edit_row = QHBoxLayout()
		deauth_packets_edit_row.addWidget(QLabel('Пакетов деавторизации за раз'))
		deauth_packets_edit_row.addWidget(self.deauth_packets_edit)
		deauth_packets_edit_row.addStretch()

		self.deauth_attempts_edit = QSpinBox()
		self.deauth_attempts_edit.setRange(1, 100)
		self.deauth_attempts_edit.setValue(3)
		deauth_attempts_edit_row = QHBoxLayout()
		deauth_attempts_edit_row.addWidget(QLabel('Попыток деавторизации'))
		deauth_attempts_edit_row.addWidget(self.deauth_attempts_edit)
		deauth_attempts_edit_row.addStretch()	
		
		self.deauth_reason_combo = QComboBox()
		
		for code, text in self.deauth_reasons.items():
			self.deauth_reason_combo.addItem(f"{code} : {text}", code)
			
		index = self.deauth_reason_combo.findData(3)
		if index != -1:
			self.deauth_reason_combo.setCurrentIndex(index)
		
		deauth_reason_combo_row = QHBoxLayout()
		deauth_reason_combo_row.addWidget(QLabel('Причина деавторизации'))
		deauth_reason_combo_row.addWidget(self.deauth_reason_combo)
		deauth_reason_combo_row.addStretch()
		
		self.deauth_timeout_edit = QSpinBox()
		self.deauth_timeout_edit.setRange(1, 10)
		self.deauth_timeout_edit.setValue(3)
		deauth_timeout_edit_row = QHBoxLayout()
		deauth_timeout_edit_row.addWidget(QLabel('Максимальное время ожидания EAPOL-фрейма'))
		deauth_timeout_edit_row.addWidget(self.deauth_timeout_edit)
		deauth_timeout_edit_row.addWidget(QLabel('сек'))
		deauth_timeout_edit_row.addStretch()
		
		settings_layout.addLayout(deauth_packets_edit_row)
		settings_layout.addLayout(deauth_attempts_edit_row)
		settings_layout.addLayout(deauth_reason_combo_row)
		settings_layout.addLayout(deauth_timeout_edit_row)
		
		frame_in_layout = QHBoxLayout()
		frame_in_layout.addLayout(status_layout, 1)
		frame_in_layout.addLayout(settings_layout, 1)
				
		frame = QFrame()
		frame.setLayout(frame_in_layout)
		frame.setFrameShape(QFrame.StyledPanel)
		
		frame_out_layout = QHBoxLayout()
		frame_out_layout.setContentsMargins(0, 0, 0, 0)
		frame_out_layout.addWidget(frame)
		
		buttons_layout = QHBoxLayout()
		self.btn_start_scan = QPushButton('Мониторинг')
		self.btn_stop_scan = QPushButton('Стоп')
		self.btn_deauth = QPushButton('Деавторизовать')
		
		self.btn_start_scan.setIcon(QIcon('icons/refresh.png'))
		self.btn_start_scan.setIconSize(QSize(24, 24))

		self.btn_stop_scan.setIcon(QIcon('icons/stop.png'))
		self.btn_stop_scan.setIconSize(QSize(24, 24))
		
		self.btn_deauth.setIcon(QIcon('icons/scan.png'))
		self.btn_deauth.setIconSize(QSize(24, 24))		
		
		buttons_layout.addWidget(self.btn_start_scan)
		buttons_layout.addWidget(self.btn_stop_scan)
		buttons_layout.addWidget(self.btn_deauth)
		buttons_layout.addStretch()
		buttons_layout.setContentsMargins(5, 5, 5, 5)
		
		self.stations_table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['MAC', 'Vendor', 'RSSI', 'Frames', 'Rate', 'Modulation'])

		self.stations_table.setModel(self.model)
		self.stations_table.horizontalHeader().setStretchLastSection(True)
		self.stations_table.setEditTriggers(QTableView.NoEditTriggers)
		self.stations_table.setShowGrid(False)
		self.stations_table.verticalHeader().setVisible(False)
		self.stations_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		
		self.progress_delegate = ProgressBarDelegate(self.stations_table)
		self.stations_table.setItemDelegateForColumn(2, self.progress_delegate)
		self.stations_table.setIconSize(QSize(32, 32))
		
		row = []
		row.append(QStandardItem(QIcon('icons/signal.png'), '80:32:44:ce:5d:fe'))
		row.append(QStandardItem('Intel Corporation'))
		row.append(QStandardItem('-54'))
		row.append(QStandardItem('418'))
		row.append(QStandardItem('24 mB/s'))
		row.append(QStandardItem('64-QAM MIMO'))
		self.model.appendRow(row)
		
		row_number = self.model.rowCount() -1
		self.stations_table.setRowHeight(row_number, 40)
		
		self.stations_table.setColumnWidth(0, 150)
		self.stations_table.setColumnWidth(1, 220)
		self.stations_table.setColumnWidth(2, 300)
		self.stations_table.setColumnWidth(3, 55)
		self.stations_table.setColumnWidth(4, 80)
		
		main_layout = QVBoxLayout()
		main_layout.addWidget(QLabel('<b>Network Info</b>'))
		main_layout.addLayout(frame_out_layout)
		main_layout.addLayout(buttons_layout)
		main_layout.addWidget(self.stations_table)
		main_layout.addWidget(QLabel('<b>Лог</b>'))
		main_layout.addWidget(QTextEdit())
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = DeauthDialog()
	window.show()
	sys.exit(app.exec_())

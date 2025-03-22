#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QStatusBar, QCheckBox, QMenu, QAction
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QPen, QPainterPath, QFont, QPixmap, QColor
from PyQt5.QtCore import Qt, QSize, QTimer, pyqtSignal, QObject, QMetaObject, Q_ARG, pyqtSlot, QItemSelection, QItemSelectionModel, QPoint, QRect

import sys
import json
import csv
import re
import os
import time
import signal
import threading
import subprocess
import random
import contextlib
import pcapy

from scapy.all import *
from target import DeauthDialog

import checker
import hexdump
import wifiman
#import deauth_dlg
import misc

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
    return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class SSIDColorDelegate(QStyledItemDelegate):
	def paint(self, painter, option, index):
		data = index.data(Qt.UserRole +1)

		if data == "hidden":
			painter.save()

			icon = index.data(Qt.DecorationRole)
			icon_size = option.decorationSize.width() if icon else 0
			padding = 5  # Отступ от иконки до текста
			text_x = option.rect.x() + icon_size + (padding if icon else 0)
			text_y = option.rect.y() + 2  # Чуть ниже, чтобы не прилипало к верху
			font_bold = QFont()
			font_bold.setBold(True)
			font_bold.setUnderline(True)
			font_bold.setItalic(True)
			font_normal = QFont()
			font_normal.setItalic(True)
			font_metrics = painter.fontMetrics()
			line_height = font_metrics.height()

			if icon:
				icon_rect = QRect(option.rect.x()+2, option.rect.y() +2, icon_size, icon_size)
				icon.paint(painter, icon_rect, Qt.AlignVCenter)
	
			painter.setFont(font_bold)
			painter.setPen(option.palette.text().color())
			painter.setPen(QColor('#ff0000'))
			painter.drawText(text_x, text_y, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, '<hidden>')
			painter.setFont(font_normal)
			painter.setPen(QColor(Qt.gray))

			pending_icon = QIcon('icons/pending.png')
			pending_icon_rect = QRect(option.rect.x() + icon_size + 5, option.rect.y() + line_height +5, 16, 16)
			pending_icon.paint(painter, pending_icon_rect, Qt.AlignVCenter)

			painter.drawText(text_x +20, text_y + line_height, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, "(pending)")

			painter.restore()
		else:
			super().paint(painter, option, index)


class MonoFontDeligate(QStyledItemDelegate):
	def initStyleOption(self, option, index):
		super().initStyleOption(option, index)
		#if index.column() == 0:
		option.font = QFont("monospace", 9)
		#option.font = QFont("Courier New", 9)
	
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
			#progress_option.setStyleSheet("QProgressBar {border: 2px solid grey; border-radius: 5px; text-align: center;}")
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar , progress_option, painter)
			#option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None

class MyTableView(QTableView):
	def mousePressEvent(self, event):
		index = self.indexAt(event.pos())
		if not index.isValid():
			self.btn_refresh.setEnabled(False)
		else:
			super().mousePressEvent(event)
			self.btn_refresh.setEnabled(True)

class StationsTable(QWidget):
	def __init__(self, parent=None):
		super().__init__(parent)
		layout = QVBoxLayout(self)
		layout.setContentsMargins(35, 5, 5, 5)
		
		top_layout = QHBoxLayout()
		top_layout.setContentsMargins(0, 0, 0, 0)
		
		self.assocIconLabel = QLabel()
		self.assocIconLabel.setPixmap(QPixmap('icons/satellite-dish.png').scaled(24, 24, Qt.KeepAspectRatio))
		self.assocIconLabel.setFixedWidth(24)
		
		assocLabelFont = QFont()
		assocLabelFont.setBold(True)
		assocLabelFont.setPointSize(12)
		self.assocLabel = QLabel('Associated stations:')
		self.assocLabel.setFont(assocLabelFont)
		
		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'Rate', 'Modulation'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.table.setItemDelegateForColumn(1, self.progress_delegate)

		self.table.setColumnWidth(0, 170)
		self.table.setColumnWidth(1, 300)
		self.table.setColumnWidth(4, 55)
		self.table.setColumnWidth(5, 80)
		
		top_layout.addWidget(self.assocIconLabel)
		top_layout.addWidget(self.assocLabel)
		layout.addLayout(top_layout)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def update_data(self, ssid, stations):
		self.model.setRowCount(0)
		
		self.assocLabel.setText(f'Associated stations for "{ssid}":')
		
		for station in stations:
			first_item = QStandardItem(QIcon('icons/signal.png'), str(station.get('station_MAC', "")))
			row = [first_item]
			for col in ['station_dBm_AntSignal', 'station_Frames', 'station_Rate', 'station_ChannelFlags']:
				row.append(QStandardItem(str(station.get(col, ""))))
			self.model.appendRow(row)
			
			row_number = self.model.rowCount() -1
			self.table.setRowHeight(row_number, 40)
			

class MainWindow(QMainWindow):
	def __init__(self):
		super().__init__()
		
		self.wifi = misc.WiFiPhyManager()

		self.networks = {}
		self.hidden_networks = {}
		self.supported_channels = []
		self.interface = None
		self.pcapfile = None
		self.pcapfilelen = 0
		self.pcapfilepos = 0
		self.online = 0
		
		self.interrupt_flag = False
		self.ouiDB = {}
		self.ouiCSV_Data = None
		self.load_oui_csv()
		
		self.statusbar = QStatusBar()
		self.setStatusBar(self.statusbar)
		
		self.statusLabel = QLabel('Interface not selected')
		
		self.interfaceIconLabel = QLabel()
		self.interfaceIconLabel.setPixmap(QPixmap('icons/ethernet.png').scaled(26, 26, Qt.KeepAspectRatio))
		
		self.networksIconLabel = QLabel()
		self.networksIconLabel.setPixmap(QPixmap('icons/menu.png').scaled(24, 24, Qt.KeepAspectRatio))
		
		self.timerIconLabel = QLabel()
		self.timerIconLabel.setPixmap(QPixmap('icons/clock-time.png').scaled(24, 24, Qt.KeepAspectRatio))
		
		self.netCountLabel = QLabel('Networks: 0')
		self.statusLabel.setFixedWidth(350)
		self.netCountLabel.setFixedWidth(250)
		self.workTimeLabel = QLabel('0d 00:00:00')

		self.statusbar.addWidget(self.interfaceIconLabel)
		self.statusbar.addWidget(self.statusLabel)
		self.statusbar.addWidget(self.networksIconLabel)
		self.statusbar.addWidget(self.netCountLabel)
		self.statusbar.addWidget(self.timerIconLabel)
		self.statusbar.addWidget(self.workTimeLabel)
		
		self.workTimer = QTimer()
		self.workTimer.setInterval(1000)
		self.workTimer.timeout.connect(self.on_work_timer)
				
		self.workSec = 0
		self.workMin = 0
		self.workHour = 0
		self.workDays = 0
		
		central_widget = QWidget()
		main_layout = QVBoxLayout()
		main_layout.setContentsMargins(0, 0, 0, 0)
		
		self.sniffing = False
		self.hopper_thread = None
		self.stop_hopping = threading.Event()
		
		self.setWindowTitle("PyQt WiFi scanner")
		self.setWindowIcon(QIcon('icons/satellite-dish.png'))
		
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = xrandr_wxh.split('x')
		w = 1250
		h = 530
		x = round((int(wh[0]) / 2) - (w / 2))
		y = round((int(wh[1]) / 2) - (h / 2))
		
		self.setGeometry(x, y, w, h)
		
		self.btn_open = QPushButton('Открыть pcap')
		self.btn_open.setIcon(QIcon('icons/open-folder.png'))
		self.btn_open.setIconSize(QSize(24, 24))
		self.btn_wifi = QPushButton('Выбор адаптера')
		self.btn_wifi.setIcon(QIcon('icons/ethernet.png'))
		self.btn_wifi.setIconSize(QSize(24, 24))
		self.btn_scan = QPushButton('Сканировать')
		self.btn_scan.setIcon(QIcon('icons/refresh.png'))
		self.btn_scan.setIconSize(QSize(24, 24))
		self.btn_stop = QPushButton('Остановить')
		self.btn_stop.setIcon(QIcon('icons/cancelled.png'))
		self.btn_stop.setIconSize(QSize(24, 24))
		self.btn_targ = QPushButton('Выбор цели')
		self.btn_targ.setIcon(QIcon('icons/target.png'))
		self.btn_targ.setIconSize(QSize(24, 24))
		
		self.btn_wifi.clicked.connect(self.show_wifiman_dialog)
		self.btn_scan.clicked.connect(self.scan_networks)
		self.btn_stop.clicked.connect(self.stop_scan)
		self.btn_targ.clicked.connect(self.target_select)
		self.btn_open.clicked.connect(self.open_pcap)
		
		self.btn_scan.setEnabled(False)
		self.btn_stop.setEnabled(False)
		#self.btn_targ.setEnabled(False)
		
		self.wps_checkbox = QCheckBox('Только WPS-сети')
		self.sta_checkbox = QCheckBox('Показывать подключенные станции')
		self.sta_checkbox.setChecked(Qt.Checked)
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_open)
		top_layout.addWidget(self.btn_wifi)
		top_layout.addWidget(self.btn_scan)
		top_layout.addWidget(self.btn_stop)
		top_layout.addWidget(self.btn_targ)
		top_layout.addWidget(self.wps_checkbox)
		top_layout.addWidget(self.sta_checkbox)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()
		
		self.table = QTableView()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		
		self.model = QStandardItemModel()
		header_labels = ["SSID", "BSSID", "Ch", "Enc", "Cipher", "AKM", "WPS", "Hardware", "Lck", "RSSI", "Beacons"]
		self.model.setHorizontalHeaderLabels(header_labels)
		self.table.setModel(self.model)
		
		self.table.setColumnWidth(0, 200)      # SSID
		self.table.setColumnWidth(1, 210)      # BSSID
		self.table.setColumnWidth(2, 50)       # CH
		self.table.setColumnWidth(3, 90)       # ENC
		self.table.setColumnWidth(4, 90)       # CIPHER
		self.table.setColumnWidth(5, 70)       # AKM
		self.table.setColumnWidth(6, 50)       # WPS
		self.table.setColumnWidth(7, 100)      # HARDWARE
		self.table.setColumnWidth(8, 50)       # LCK
		self.table.setColumnWidth(9, 250)      # RSSI
		self.table.setColumnWidth(10, 50)      # BEACONS

		self.table.setItemDelegateForColumn(0, SSIDColorDelegate(self.table))
		self.table.setItemDelegateForColumn(1, MonoFontDeligate(self.table))
		self.table.setItemDelegateForColumn(7, MonoFontDeligate(self.table))
		self.table.setItemDelegateForColumn(9, ProgressBarDelegate(self.table))
		self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setIconSize(QSize(32, 32))
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.doubleClicked.connect(self.open_hexdump_window)
		self.previous_progress_values = {}
		#self.model.dataChanged.connect(self.on_update_table)

		self.setCentralWidget(central_widget)
		central_widget.setLayout(main_layout)

		self.setContextMenuPolicy(Qt.CustomContextMenu)
		self.table.customContextMenuRequested.connect(self.show_context_menu)
	
	def pcap_packets_count(self, file):
		cap = pcapy.open_offline(file)
		count = 0
		while True:
			header, _ = cap.next()
			if not header:
				break
			count += 1
		return count

	def open_pcap(self):
		file_path, _ = QFileDialog.getOpenFileName(None, "", "", "Все файлы (*);;Файлы захвата (*.pcap)")
		if file_path:
			self.interrupt_flag = False
			self.pcapfile = file_path
			self.pcapfilelen = self.pcap_packets_count(file_path)
			self.pcapfilepos = 0
			self.interfaceIconLabel.setPixmap(QPixmap('icons/binary-code.png').scaled(26, 26, Qt.KeepAspectRatio))			
			self.networks = {}
			self.clear_list()
			self.pcapfilepos = 0
			self.update_pcapfile_status_pos(0)	
			self.sniff_thread = threading.Thread(target=self.sniff_packets_offline, daemon=True)
			self.sniff_thread.start()
			self.btn_open.setEnabled(False)
			self.btn_scan.setEnabled(False)
			self.btn_wifi.setEnabled(False)
			self.btn_stop.setEnabled(True)
		
	def update_pcapfile_status_pos(self, pos):
		self.statusLabel.setText(f"{os.path.basename(self.pcapfile)}, ({self.pcapfilepos}/{self.pcapfilelen})")
	
	def sniff_packets_offline(self):
		sniff(offline=self.pcapfile, prn=self.radio_packets_handler, store=0, stop_filter=lambda pkt: (self.interrupt_flag))
	
	def show_context_menu(self, pos: QPoint):
		index = self.indexAt(pos)
		if not index.isValid():
			return
		
		menu = QMenu(self)

		action1 = QAction(QIcon("icons/unlocked.png"), "Редактировать", self)
		action2 = QAction(QIcon("icons/target.png"), "Удалить", self)
		menu.addAction(action1)
		menu.addAction(action2)
		menu.exec_(self.viewport().mapToGlobal(pos))

	def target_select(self):
		selected_indexes = self.table.selectionModel().selectedRows()
		if selected_indexes:
			if self.interface:
				row = selected_indexes[0].row()
				model = self.table.model()
				bssid = model.data(model.index(row, 1), Qt.UserRole)
				channel = model.data(model.index(row, 2))
				if bssid:
					targetWindow = DeauthDialog(self.interface, bssid, channel, self)
					targetWindow.exec_()
			else:
				QMessageBox.critical(self, "Error", "Интерфейс не выбран!")
	
	def load_oui_csv(self):
		with open('data/oui.csv', newline='', encoding='utf-8') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				if len(row) >= 3:
					oui = row[1].upper()
					vendor = row[2].strip()
					self.ouiDB[oui] = vendor
	
	def get_mac_vendor(self, mac):
		mac_prefix = mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6]
		return self.ouiDB.get(mac_prefix, "Unknown")
	
	def get_mac_vendor_mixed(self, mac):
		if mac:
			vendor = self.get_mac_vendor(mac)
			if vendor != 'Unknown':
				vendor_cleaned = re.sub(r'[ ,.""]', '', vendor)
				return f"{vendor_cleaned[:8]}_{mac[9:].upper()}"
			else:
				return mac.upper()
		else:
			return
	
	def startWorkTimer(self):
		self.workTimeLabel.setText('0d 00:00:00')
		self.workTimer.start()
	
	def on_work_timer(self):
		self.workSec += 1
		if self.workSec > 59:
			self.workSec = 0
			self.workMin += 1
		elif self.workMin > 59:
			self.workMin = 0
			self.workHour += 1 
		elif self.workHour > 24:
			self.workSec = 0
			self.workMin = 0
			self.workHour = 0
			self.workDays += 1
		
		self.workTimeLabel.setText(f"{self.workDays}d {self.workHour:02d}:{self.workMin:02d}:{self.workSec:02d}")
	
	def show_wifiman_dialog(self):
		wifiman_dialog = wifiman.WiFiManager(self)
		wifiman_dialog.exec_()
		
		if wifiman_dialog.result() == QDialog.Accepted:
			result = wifiman_dialog.select_iface()
			if not result.get('interface') is None:
				self.interface = result.get('interface', None)
				self.supported_channels = result.get('supported_channels', None)
				self.interfaceIconLabel.setPixmap(QPixmap('icons/ethernet.png').scaled(26, 26, Qt.KeepAspectRatio))
				self.statusLabel.setText(f"Interface: {self.interface}, CH: ?")
				self.btn_scan.setEnabled(True)
	
	def on_update_table(self, topLeft, bottomRight, roles):
		model = self.table.model()
		
		for row in range(topLeft.row(), bottomRight.row() +1):
			index = model.index(row, 7)
			item = self.model.item(row, 7)

			if not (topLeft.column() <= 8 <= bottomRight.column()):
				continue

			new_value = item.data(Qt.UserRole)
			old_value = self.previous_progress_values.get((row, 7), 0)
			
			if new_value is None or old_value is None:
				continue
				
			if new_value != old_value:
				self.timer = QTimer()
				self.timer.setInterval(5)
				self.timer.timeout.connect(lambda: self.update_progress(item, row, int(old_value), int(new_value)))
				self.timer.start()
				self.previous_progress_values[(row, 7)] = new_value
	
	def update_progress(self, item, row, old_value, new_value):
		if old_value < new_value:
			old_value += 1
			item.setText(str(old_value))
		elif old_value > new_value:
			old_value -= 1
			item.setText(str(old_value))
		else:
			self.timer.stop()
			self.timer.deleteLater()

	def open_hexdump_window(self, index):
		item = self.model.itemFromIndex(index)
		bssid = self.model.itemFromIndex(self.model.index(index.row(), 1)).data(Qt.UserRole)
		ssid = self.model.itemFromIndex(self.model.index(index.row(), 0)).text()
		network_info = self.networks.get(bssid)
		
		if network_info:
			pkt = network_info.get('packet')
			if pkt:
				hexdump_dialog = hexdump.HexDumpDialog(ssid, pkt, self)
				hexdump_dialog.exec_()

	def stop_scan(self):
		self.btn_stop.setEnabled(False)
		self.btn_open.setEnabled(True)
		self.sniffing = False
		self.interrupt_flag = True
		self.stop_hopping.set()
		self.btn_wifi.setEnabled(True)

		if self.hopper_thread:
			self.hopper_thread.join(timeout=1)
			self.hopper_thread = None
			self.sniff_thread.join()
			self.btn_scan.setEnabled(True)
			self.btn_wifi.setEnabled(True)
			self.wps_checkbox.setEnabled(True)
			self.workTimer.stop()
			self.statusLabel.setText(f"Interface: {self.interface}, CH: ?")

	def scan_networks(self):
		global interface
		if self.wifi.get_iface_state(self.interface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейс {interface} выключен!")
			return
			
		if self.wifi.iface_exists(self.interface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейса {interface} не существует!")
			return
		
		self.clear_list()
		self.btn_stop.setEnabled(True)
		self.btn_scan.setEnabled(False)
		self.btn_wifi.setEnabled(False)
		self.btn_open.setEnabled(False)
		self.wps_checkbox.setEnabled(False)
		self.networks = {}

		if self.sniffing:
			return
		
		self.interrupt_flag = False
		self.online = 1
		self.startWorkTimer()
		self.sniffing = True
		self.stop_hopping.clear()
		self.hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
		self.hopper_thread.start()
		self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
		self.sniff_thread.start()
	
	def safe_chlabel_set_ch(self, ch):
		QMetaObject.invokeMethod(self, "__update_ch_label", Qt.QueuedConnection, Q_ARG(str, ch))
	
	@pyqtSlot(str)
	def __update_ch_label(self, ch):
		self.statusLabel.setText(f"Interface: {self.interface}, CH: {ch}")
	
	def channel_hopper(self):
		while not self.stop_hopping.is_set() or not self.interrupt_flag:  
			if self.stop_hopping.is_set():
				break
			if self.interrupt_flag:
				break
			ch = random.choice(self.supported_channels)
			self.wifi.switch_iface_channel(self.interface, ch)
			self.safe_chlabel_set_ch(str(ch))
			time.sleep(0.3)
			#for ch in self.supported_channels:
			#	self.wifi.switch_iface_channel(self.interface, ch)
			#	self.safe_chlabel_set_ch(str(ch))
			#	time.sleep(1)

	def sniff_packets(self):
		sniff(iface=self.interface, prn=self.radio_packets_handler, store=0, stop_filter=lambda pkt: (self.interrupt_flag))

	def clear_list(self):
		while self.model.rowCount() > 0:
			self.model.removeRow(0)
	
	def safe_add_table_item(self, json_data):
		QMetaObject.invokeMethod(self, "__add_table_item", Qt.QueuedConnection, Q_ARG(str, json_data))
		
	@pyqtSlot(str)
	def __add_table_item(self, json_data):
		rows = []
		data = json.loads(json_data)
		is_hidden = data.get('hidden', None)

		for key, value in data.items():
			if key in ['ssid', 'bssid', 'channel', 'enc', 'cipher', 'akm', 'wps_version', 'vendor', 'chip', 'locked', 'signal', 'beacons']:
				if key == 'ssid':
					item = QStandardItem(QIcon('icons/wifi-router.png'), value)
					if is_hidden:
						item.setData('hidden', Qt.UserRole +1)	
				elif key == 'bssid':
					item = QStandardItem(str(value.get('mixed', None)))
					item.setData(value.get('mac', None), Qt.UserRole)
				elif key == 'cipher' or key == 'akm':
					item = QStandardItem(','.join(value))
				elif key == 'enc':
					item = QStandardItem('/'.join(value))
				else:
					item = QStandardItem(str(value))
				rows.append(item)
		
		self.model.appendRow(rows)
		row_number = self.model.rowCount() -1
		self.table.setRowHeight(row_number, 40)
		
		self.previous_progress_values[(row_number, 9)] = data['signal']
	
	def safe_update_item_by_bssid(self, bssid, item, data):
		QMetaObject.invokeMethod(self, "__update_item_by_bssid", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(int, item), Q_ARG(str, data))
	
	def safe_update_item_data_by_bssid(self, bssid, item, data):
		QMetaObject.invokeMethod(self, "__update_item_data_by_bssid", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(int, item), Q_ARG(str, data))
	
	@pyqtSlot(str, int, str)
	def __update_item_by_bssid(self, bssid, item, data):
		for row in range(self.model.rowCount()):
			item_bssid = self.model.item(row, 1)
			if item_bssid and item_bssid.text().upper() == bssid.upper():
				item = self.model.item(row, item) 
				if item:
					item.setText(str(data))
					item.setData(data, Qt.UserRole)
					
	@pyqtSlot(str, int, str)
	def __update_item_data_by_bssid(self, bssid, item, data):
		for row in range(self.model.rowCount()):
			item_bssid = self.model.item(row, 1)
			if item_bssid and item_bssid.text().upper() == bssid.upper():
				item = self.model.item(row, item) 
				if item:
					item.setData(data, Qt.UserRole)
	
	def safe_add_StationsList(self, bssid, stations_json):
		QMetaObject.invokeMethod(self, "__add_subitem", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(str, stations_json))
	
	def has_nested_exists(self, row):
		for col in range(self.model.columnCount()):
			index = self.model.index(row, col)
			widget = self.table.indexWidget(index)
			if isinstance(widget, QWidget):
				return True
		
		return False
		
	@pyqtSlot(str, str)
	def __add_subitem(self, bssid, stations_json):
		stations = json.loads(stations_json)
		for row in range(self.model.rowCount()):
			index = self.table.model().index(row, 0)
			ssid = self.table.model().data(index)
			
			if self.model.item(row, 1).text() == bssid:
				if self.has_nested_exists(row + 1):					
					subitem_index = self.model.index(row + 1, 0)
					stations_table = self.table.indexWidget(subitem_index)
					stations_table.update_data(ssid, stations)
					
					num_rows = stations_table.model.rowCount()
					new_height = max(75, ((num_rows * 40) + 64))
					self.table.setRowHeight(row +1, new_height)
				else:
					subitem = QStandardItem("")
					sub_row = [QStandardItem("") for _ in range(self.model.columnCount())]
					sub_row[0] = subitem
					self.model.insertRow(row + 1, sub_row)
					self.table.setSpan(row + 1, 0, 1, 8)
					subitem_index = self.model.index(row + 1, 0)
					stations_table = StationsTable(self)
					stations_table.update_data(ssid, stations)
					
					self.table.setIndexWidget(subitem_index, stations_table)
					self.table.setRowHeight(row +1, 103)
					
					self.table.viewport().update()
	
	def safe_update_networks_cnt(self, cnt):
		QMetaObject.invokeMethod(self, "__update_networks_cnt", Qt.QueuedConnection, Q_ARG(int, cnt))
	
	@pyqtSlot(int)
	def __update_networks_cnt(self, cnt):
		self.netCountLabel.setText(f"Networks: {cnt}")
	
	def stations_handler(self, pkt):
		ap_mac = pkt.addr1
		if ((ap_mac in self.networks) and (pkt.type == 1 and pkt.subtype in [8, 9])):
			if pkt.addr2 != 'ff:ff:ff:ff:ff:ff':
				
				wifi = misc.WiFi_Parser(pkt)
				station_MAC = pkt.addr2
				station_dBm_AntSignal = wifi.RadioTap_Attr('dBm_AntSignal')# pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
				station_ChannelFlags = wifi.RadioTap_Attr('ChannelFlags')# pkt.ChannelFlags if hasattr(pkt, 'ChannelFlags') else '?'
				station_Rate = wifi.RadioTap_Attr('Rate')# pkt.Rate if hasattr(pkt, 'Rate') else '?'
				station_Vendor = self.get_mac_vendor(station_MAC) # get_vendor_from_mac(station_MAC, oui_database)
				
				if ap_mac in self.networks:
					stations_networks = self.networks[ap_mac]['stations']

					if station_MAC in stations_networks:
						self.networks[ap_mac]['stations'][station_MAC]['station_Frames'] += 1
						self.networks[ap_mac]['stations'][station_MAC]['station_dBm_AntSignal'] = station_dBm_AntSignal
						self.networks[ap_mac]['stations'][station_MAC]['station_ChannelFlags'] = str(station_ChannelFlags)
						self.networks[ap_mac]['stations'][station_MAC]['station_Rate'] = f"{station_Rate} mB/s"
					else:
						self.networks[ap_mac]['stations'][station_MAC] = {
							'station_MAC': self.get_mac_vendor_mixed(station_MAC),
							'station_dBm_AntSignal': station_dBm_AntSignal,
							'station_ChannelFlags': str(station_ChannelFlags),
							'station_Rate': f"{station_Rate} mB/s",
							'station_Frames': 1
						}

					stations_dict = list(self.networks[ap_mac]['stations'].values())
					stations_json = json.dumps(stations_dict, default=str)
					self.safe_add_StationsList(self.get_mac_vendor_mixed(ap_mac), stations_json);		
	
	def radio_packets_handler(self, pkt):
		if self.online == 0:
			self.pcapfilepos += 1
			self.update_pcapfile_status_pos(self.pcapfilepos)

			if self.pcapfilepos == self.pcapfilelen:
				self.stop_scan()

		if not pkt.haslayer(RadioTap):
			return
		if self.sta_checkbox.isChecked():
			self.stations_handler(pkt)
		
		if not pkt.haslayer(Dot11Beacon):
			return
		
		bssid = pkt.addr3
		wifi = misc.WiFi_Parser(pkt)
		signal = wifi.RadioTap_Attr('dBm_AntSignal')
		channel = wifi.freq_channels.get(wifi.RadioTap_Attr('Channel'), None)
		
		if channel is None:
			return
		if signal is None:
			return
		if bssid is None:
			return
			
		if not bssid in self.networks:
			ssid = wifi.ssid()
			rsn_info = wifi.get_rsn_info()
			enc = wifi.get_enc_type()
			hardware = wifi.get_vendor_string()
			wps_info = wifi.wps_info()
			wps_version = '-'
			wps_locked = '-'
			
			if self.wps_checkbox.isChecked() and not wifi.wps_info():
				return
			
			if wps_info:
				wps_version = wps_info['version']
				if wps_info['locked']:
					wps_locked = 'Yes'
				else:
					wps_locked = 'No'
			
			
			if ssid is None:
				if not bssid in self.hidden_networks:
					self.hidden_networks[bssid] = {
						'bssid': bssid,
						'channel': channel
					}
		
			self.networks[bssid] = {
				'ssid': ssid,
				'bssid': {
					'mixed' : self.get_mac_vendor_mixed(bssid),
					'mac': bssid
				},
				'channel': channel,
				'enc': enc,
				'cipher': rsn_info['pairwise'],
				'akm': rsn_info['akm'],
				'wps_version': wps_version,
				'chip': hardware,
				'locked': wps_locked,
				'signal': int(signal),
				'beacons': 1,
				'packet': pkt,
				'hidden': ssid is None,
				'stations': {},
			}
			
			self.safe_update_networks_cnt(len(self.networks))

			json_data = json.dumps({k: v for k, v in self.networks[bssid].items() if k not in ['packet', 'stations']})
			self.safe_add_table_item(json_data)
		else:
			self.networks[bssid]['channel'] = channel
			self.networks[bssid]['signal'] = signal
			self.networks[bssid]['beacons'] +=1
			self.networks[bssid]['packet'] = pkt
			beacons = self.networks[bssid]['beacons']
			
			self.safe_update_item_by_bssid(bssid, 2, str(channel))
			self.safe_update_item_by_bssid(bssid, 9, str(signal))
			self.safe_update_item_by_bssid(bssid, 10, str(beacons))		

if __name__ == '__main__':
	if checker.check_all_need():
		app = QApplication(sys.argv)
		window = MainWindow()
		window.show()
		sys.exit(app.exec_())

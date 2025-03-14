#!/usr/bin/env python3

import sys
import subprocess

from PyQt5.QtWidgets import (
	QDialog, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt5.QtCore import Qt, QSize, QItemSelection
from misc import WiFiPhyManager

class WiFiManager(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setWindowTitle("Выбор Wifi адаптера")
		self.setWindowIcon(QIcon('icons/ethernet.png'))

		self.wifi = WiFiPhyManager()
		self.devices = self.wifi.handle_lost_phys()

		self.setGeometry(*self._center_window(1120, 520))

		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 7, self)
		self.model.setHorizontalHeaderLabels(['PHY', 'Interface', 'MAC', 'Driver', 'Chipset', 'State', 'Mode'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.doubleClicked.connect(self.select_iface)

		# Настройки ширины колонок
		col_widths = [90, 150, 150, None, 350, None, None]
		for i, width in enumerate(col_widths):
			if width:
				self.table.setColumnWidth(i, width)

		# Кнопки
		self.btn_refresh = self._create_button("Обновить", "icons/refresh.png", self.update_list)
		self.btn_updown = self._create_button("Поднять", "icons/upward-arrow.png", self.updown_iface, False)
		self.btn_mode = self._create_button("Режим мониторинга", "icons/connections.png", self.switch_iface_mode, False)

		# Размещение кнопок
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_refresh)
		top_layout.addWidget(self.btn_updown)
		top_layout.addWidget(self.btn_mode)
		top_layout.addStretch()

		# Основной layout
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		self.setLayout(main_layout)

		self.update_list()

	def _center_window(self, w, h):
		""" Возвращает координаты для центрирования окна. """
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode().strip()
		screen_w, screen_h = map(int, xrandr_wxh.split('x'))
		return round((screen_w - w) / 2), round((screen_h - h) / 2), w, h

	def _create_button(self, text, icon, callback, enabled=True):
		""" Универсальная функция для создания кнопки. """
		btn = QPushButton(text)
		btn.setIcon(QIcon(icon))
		btn.setIconSize(QSize(24, 24))
		btn.setEnabled(enabled)
		btn.clicked.connect(callback)
		return btn

	def _get_selected_row(self):
		""" Возвращает индекс выбранной строки или None. """
		indexes = self.table.selectionModel().selectedIndexes()
		return indexes[0].row() if indexes else None

	def _get_value(self, row, column, role=Qt.DisplayRole):
		""" Универсальный метод получения данных из таблицы. """
		return self.model.data(self.model.index(row, column), role)

	def select_iface(self):
		""" Выбор интерфейса по двойному клику. """
		row = self._get_selected_row()
		if row is None:
			return

		phy = self._get_value(row, 0).lower()
		iface = self._get_value(row, 1)

		if not self.wifi.iface_exists(iface):
			QMessageBox.critical(self, "Ошибка", f"Интерфейса {iface} не существует!")
			self.update_list()
			return

		self.accept()
		return {"interface": iface, "supported_channels": self.wifi.get_phy_supported_channels(phy)}

	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		""" Обновление состояния кнопок при выборе адаптера. """
		row = self._get_selected_row()
		enabled = row is not None
		self.btn_updown.setEnabled(enabled)
		self.btn_mode.setEnabled(enabled)

		if not enabled:
			return

		# Обновляем кнопки в зависимости от состояния
		state = self._get_value(row, 5, Qt.UserRole)
		mode = self._get_value(row, 6, Qt.UserRole + 1)

		print(mode)

		self.btn_mode.setText('В режим станции' if mode == 803 else 'В режим мониторинга')
		self.btn_mode.setIcon(QIcon('icons/global-network.png' if mode == 803 else 'icons/connections.png'))

		self.btn_updown.setText('Отключить' if state else 'Поднять')
		self.btn_updown.setIcon(QIcon('icons/down-arrow.png' if state else 'icons/upward-arrow.png'))

	def update_list(self):
		""" Обновление списка Wi-Fi адаптеров. """
		self.devices = self.wifi.handle_lost_phys()
		self.model.setRowCount(0)

		for val in self.devices.values():
			items = []
			for key, v in val.items():
				if key == 'channels':
					continue
				item = QStandardItem(QIcon('icons/ethernet.png'), v) if key == 'phydev' else QStandardItem(str(v))
				if key == 'state':
					item = QStandardItem('UP' if v else 'DOWN')
					item.setData(v, Qt.UserRole)
				if key == 'mode':
					item = QStandardItem(self.wifi.iface_types.get(v, 'Unknown'))
					item.setData(v, Qt.UserRole +1)
				items.append(item)

			self.model.appendRow(items)
			self.table.setRowHeight(self.model.rowCount() - 1, 40)

	def updown_iface(self):
		""" Включение/выключение Wi-Fi адаптера. """
		row = self._get_selected_row()
		if row is None:
			return

		phy = self._get_value(row, 0).lower()
		iface = self._get_value(row, 1).lower()
		state = self._get_value(row, 5, Qt.UserRole)

		self.wifi.set_phy_link(phy, 'down' if state else 'up')
		self.update_list()

	def switch_iface_mode(self):
		""" Переключение режима адаптера. """
		row = self._get_selected_row()
		if row is None:
			return

		phy = self._get_value(row, 0).lower()
		iface = self._get_value(row, 1).lower()
		mode = self._get_value(row, 6, Qt.UserRole + 1)

		set_mode = self.wifi.set_phy_80211_station if mode == 803 else self.wifi.set_phy_80211_monitor
		set_mode(phy)

		if self.wifi.get_phy_mode(phy) != (1 if mode == 803 else 803):
			QMessageBox.critical(self, "Ошибка", f"Не возможно переключить {iface}!")

		self.update_list()

#!/usr/bin/env python3

import sys
import subprocess
import time

from PyQt5.QtWidgets import (
	QDialog, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt5.QtCore import Qt, QSize, QItemSelection

import misc

class WiFiManager(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setWindowTitle("Выбор Wifi адаптера")
		self.setWindowIcon(QIcon('icons/ethernet.png'))

		self.wifi = misc.WiFiPhyManager()
		self.devices = self.wifi.handle_lost_phys()
		
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = xrandr_wxh.split('x')
		w = 1120
		h = 520
		x = round((int(wh[0]) / 2) - (w / 2))
		y = round((int(wh[1]) / 2) - (h / 2))
		self.setGeometry(x, y, w, h)
		
		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['PHY', 'Interface', 'MAC', 'Driver', 'Chipset', 'State', 'Mode'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.doubleClicked.connect(self.select_iface)

		self.table.setColumnWidth(0, 90)
		self.table.setColumnWidth(1, 150)
		self.table.setColumnWidth(2, 150)
		self.table.setColumnWidth(4, 350)

		self.btn_refresh = QPushButton('Обновить')
		self.btn_updown = QPushButton('Поднять')
		self.btn_mode = QPushButton('Режим мониторинга')
		
		self.btn_refresh.setIcon(QIcon('icons/refresh.png'))
		self.btn_updown.setIcon(QIcon('icons/upward-arrow.png'))
		self.btn_mode.setIcon(QIcon('icons/connections.png'))
		
		self.btn_refresh.setIconSize(QSize(24, 24))
		self.btn_updown.setIconSize(QSize(24, 24))
		self.btn_mode.setIconSize(QSize(24, 24))
		
		self.btn_updown.setEnabled(False)
		self.btn_mode.setEnabled(False)
		
		self.btn_mode.clicked.connect(self.switch_iface_mode)
		self.btn_refresh.clicked.connect(self.update_list)
		self.btn_updown.clicked.connect(self.updown_iface)
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_refresh)
		top_layout.addWidget(self.btn_updown)
		top_layout.addWidget(self.btn_mode)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
		self.update_list()
	
	def select_iface(self):
		result = {}
		selected = self.table.selectionModel().currentIndex()
		model = self.table.model()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1))

		if self.wifi.iface_exists(iface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейса {interface} не существует!")
			self.update_list()
			return
		
		result = {
			'interface': iface,
			'supported_channels': self.wifi.get_phy_supported_channels(phy)
		}
		self.accept()

		return result
		
	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		indexes = selected.indexes()
		
		if indexes:
			row = indexes[0].row()
			self.btn_updown.setEnabled(True)
			self.btn_mode.setEnabled(True)
			
			model = self.model
			state = model.itemFromIndex(model.index(row, 5)).data(Qt.UserRole)
			mode = model.itemFromIndex(model.index(row, 6)).data(Qt.UserRole +1)

			if mode == 803:
				self.btn_mode.setText('В режим станции')
				self.btn_mode.setIcon(QIcon('icons/global-network.png'))
			else:
				self.btn_mode.setText('В режим мониторинга')
				self.btn_mode.setIcon(QIcon('icons/connections.png'))

			if state == True:
				self.btn_updown.setText('Отключить')
				self.btn_updown.setIcon(QIcon('icons/down-arrow.png'))
			else:
				self.btn_updown.setText('Поднять')
				self.btn_updown.setIcon(QIcon('icons/upward-arrow.png'))
		else:
			self.btn_updown.setEnabled(False)
			self.btn_mode.setEnabled(False)
		
	def update_list(self):
		self.devices = self.wifi.handle_lost_phys()
		self.model.setRowCount(0)

		for key, val in self.devices.items():
			items = []
			for k, v in val.items():
				if k != 'channels':
					if k == 'phydev':
						item = QStandardItem(QIcon('icons/ethernet.png'), v)
					elif k == 'state':
						item = QStandardItem(self.wifi.iface_states.get(v, '-'))
						item.setData(v, Qt.UserRole)
					elif k == 'mode':
						item = QStandardItem(self.wifi.iface_types.get(v, '-'))
						item.setData(v, Qt.UserRole +1)
					else:
						item = QStandardItem(str(v))
					items.append(item)
			self.model.appendRow(items)
			row_number = self.model.rowCount() -1
			self.table.setRowHeight(row_number, 40)
	
	def updown_iface(self):
		selected = self.table.selectionModel().currentIndex()
		model = self.table.model()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1)).lower()
		state = self.table.model().data(self.table.model().index(selected.row(), 5), Qt.UserRole)
		
		if state == True:
			self.wifi.set_phy_link(phy, 'down')
			time.sleep(1)
			if self.wifi.get_phy_state(phy) != False:
				QMessageBox.critical(self, "Error", f"Не возможно отключить {iface}!")
		else:
			self.wifi.set_phy_link(phy, 'up')
			time.sleep(1)
			if self.wifi.get_phy_state(phy) != True:
				QMessageBox.critical(self, "Error", f"Не возможно включить {iface}!")
			
		self.update_list()
	
	def switch_iface_mode(self):
		selected = self.table.selectionModel().currentIndex()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1)).lower()
		mode = self.table.model().data(self.table.model().index(selected.row(), 6), Qt.UserRole +1)
		
		if mode == 803:
			self.wifi.set_phy_80211_station(phy)
			if self.wifi.get_phy_mode(phy) != 1:
				QMessageBox.critical(self, "Error", f"Не возможно переключить {iface} в режим станции!")
		else:
			self.wifi.set_phy_80211_monitor(phy)
			if self.wifi.get_phy_mode(phy) != 803:
				QMessageBox.critical(self, "Error", f"Не возможно переключить {iface} в режим мониторинга!")		
		
		self.update_list()

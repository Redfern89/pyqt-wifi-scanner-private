#!/usr/bin/env python3

import os
import time
from scapy.all import *
import signal
import threading

wps_networks = {}
interface = "radio0mon"
channels = range(1, 14)  # Диапазон каналов Wi-Fi 2.4 ГГц
stop_event = threading.Event()
interrupted = False

def handle_sigint(signum, frame):
	print("\nINTERRUPT signal detected")
	interrupted = True
	stop_event.set()  # Устанавливаем сигнал для остановки

signal.signal(signal.SIGINT, handle_sigint)

def channel_hopper():
    while not stop_event.is_set():
        for ch in channels:
            if stop_event.is_set():
                break
            #print(f"Переключаемся на канал {ch}...")
            os.system(f"iwconfig {interface} channel {ch}")
            time.sleep(2)  # Уменьшаем задержку

# Запускаем хоппинг в фоновом потоке
hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
hopper_thread.start()

def parse_wps_version(wps_ie):
    """
    Разбирает WPS IE и извлекает версию WPS.
    """
    i = 4  # Пропускаем первые 4 байта (WPS OUI: 00:50:F2:04)
    wps_version = None
    wps_2_0_possible = False  # Флаг для версии WPS 2.0
    while i < len(wps_ie):
        if len(wps_ie) < i + 4:
            break
        field_type = int.from_bytes(wps_ie[i:i+2], "big")  # Тип атрибута
        field_length = int.from_bytes(wps_ie[i+2:i+4], "big")  # Длина значения

        if field_type == 0x104A and field_length == 1:  # WPS Version (0x104A), длина всегда 1 байт
            wps_version = wps_ie[i+4]  # Возвращаем сам байт версии
        elif field_type == 0x103C and field_length == 1:  # Проверяем поле 0x103C для WPS 2.0
            wps_2_0_possible = True
        i += 4 + field_length

    if wps_version is None:  # Если версия не найдена, возвращаем None
        return None

    # Если обнаружен флаг WPS 2.0, отображаем его
    if wps_2_0_possible:
        return "2.0"

    # В противном случае, выводим как WPS 1.0
    return f"{wps_version >> 4}.{wps_version & 0xF}" if wps_version != 0x10 else "1.0"

def is_wps_disabled(pkt):
    """
    Проверяет, заблокирован ли WPS в пакете.
    Это можно сделать по отсутствию поля WPS IE или по сигналам ошибки в обмене.
    """
    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # Проверяем наличие WPS IE (221) и его поля (OUI: 00:50:F2:04)
            if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xF2\x04":
                return False  # WPS найден, значит, не заблокирован
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return True  # Если WPS IE не найден, считаем, что WPS заблокирован

def wps_packet_handler(pkt):
    debug_pkt = pkt
    if pkt.haslayer(Dot11):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else None
        if not ssid or ssid.strip() == "":  # Игнорируем скрытые сети
            return

        bssid = pkt[Dot11].addr2
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"

        # Извлекаем канал
        channel = None
        if pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:  # Канал
                    channel = ord(elt.info)
                    break
                elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

        if channel is None:
            return

        # Ищем WPS IE в пакете
        wps_ie = None
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xF2\x04":  # WPS IE
                wps_ie = elt.info
                break
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

        if wps_ie:            
            wps_version = parse_wps_version(wps_ie)
            if wps_version is None:
                return  # Не удалось определить версию

            wps_status = "Yes" if is_wps_disabled(pkt) else "No"
            
            # Проверяем, есть ли уже такая сеть в списке
            if not bssid in wps_networks:
                wps_networks[bssid] = (ssid, signal, channel, wps_version, wps_status)
                # Определяем ширину каждого столбца
                channel_width = 2
                wps_status_width = 2

                # Используем str.center() для выравнивания
                print(f"📡 {bssid} | 📶 {signal} dBm | {str(channel).center(channel_width)} | {wps_version} | {str(wps_status).center(wps_status_width)} | {ssid}")

print("🔍 Сканируем WiFi сети с WPS... (Ctrl+C для остановки)\n")
print(" BSSID                RSSI         CH   WPS    Lck     ESSID")
print("----------------------------------------------------------------")

def start_sniffing():
	while not stop_event.is_set():
		if not interrupted:
			sniff(iface=interface, prn=wps_packet_handler, store=0, timeout=1, filter="subtype beacon")

# Запускаем потоки
sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
sniffer_thread.start()

while not stop_event.is_set():
    time.sleep(0.1)  # Проверяем stop_event чаще

# Завершаем потоки
hopper_thread.join()
sniffer_thread.join()

print("Terminated")

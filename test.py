#!/usr/bin/env python3

import os
import subprocess
import re
import time

class Wifi:
	def __init__(self):
		pass
	
	def get_phy_supported_channels(self, phydev):
		channels = []
		channels_data = subprocess.run(['iw', 'phy', phydev, 'channels'], capture_output=True, text=True).stdout
		channels_data = channels_data.split('* ')[1:]
		for channel_data in channels_data:
			match = re.search(r'(\d+) MHz \[(\d+)\]', channel_data)
			if match:
				if not 'No IR' in channel_data:
					channels.append(match.group(2))
		return channels

wifi = Wifi()
print(wifi.get_phy_supported_channels('phy0'))

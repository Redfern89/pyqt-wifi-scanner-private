#!/usr/bin/env python3

import requests
import datetime
import json
import re
import os

login = 'SEXOGOLIK88'
password = '7RFxUqRi'
uri_base = 'https://bestweapon.me'

def bestweaponME_login(login, password):
	post_data = {
		'login': login,
		'password': password
	}
	ch = requests.post(f'{uri_base}/logination.php', post_data)
	cookies = {}
	
	for cookie in ch.cookies:
		cookies[cookie.name] = cookie.value
		
	with open('cookies.json', 'w') as cookie_file:
		json.dump(cookies, cookie_file)

def bestweaponME_request(path):
	if os.path.exists('cookies.json'):
		with open('cookies.json') as cookie_file:
			cookies = json.load(cookie_file)
	
	return requests.get(f'{uri_base}/{path}', cookies=cookies).content.decode('cp1251', errors='replace')

def bestweaponME_getPost(post_id):
	data = bestweaponME_request(f'post_{post_id}')
	
	title = (re.search(r"<div class='post_title2' id='main_post_title'>(.*?)<\/div>", data, re.DOTALL) or [None, None])[1]
	author = (re.search(r"<strong>Автор:.*?author=.*?'>(.*?)<\/a>", data, re.DOTALL) or [None, None])[1]
	content = (re.search(r"<span id='postmaintext'>(.*?)<\/span>", data, re.DOTALL) or [None, None])[1]
	date = (re.search(r"<strong>Дата:<\/strong>.*?date.php\?date=(\d{4}-\d{2}-\d{2})", data, re.DOTALL) or [None, None])[1]
	date = date.split('-') if date else None # Y-m-d
	if date:
		y, m, d = map(int, date)
		date = int(datetime.datetime(y, m, d, 0, 0, 0).timestamp())
	print(date)
	

bestweaponME_getPost(10112)

# Coded / Dev: ††#9999 | https://github.com/TT-Tutorials | https://gangnuker.org
# GANG TOKEN GENERATOR / Multi Tool©
# Copyright © 2022
#########################################

import os
import sys
import json
import os.path
import hashlib
import platform
import traceback
from time import sleep
from colorama import Fore
from datetime import datetime
from lib2to3.pgen2 import token
from pystyle import Write, Colors
from utilities.Settings.keyauth import api



os.system("cls")
os.system("title Key Login   \   GANG-Nuker   /  PAID VERSION")

if platform.system() == 'Windows':
    os.system('cls')
elif platform.system() == 'Linux':
    os.system('clear')
elif platform.system() == 'Darwin':
    os.system("clear && printf '\e[3J'")

def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

keyauthapp = api(
    name = "GANG-Nuker",
    ownerid = "4V5Zpc7rGS",
    secret = "6e073e4e811d3b4b3ec9881145a404d79b333dc2100bb5245103f69cb6dbbf9f",
    version = "1.0",
    hash_to_check = getchecksum()
)

def answer():

    key = input('[\x1b[95mX\x1b[95m\x1B[37m] Licence Key?: ')
    keyauthapp.license(key)


answer()

#print(f"[{Fore.LIGHTYELLOW_EX}!{Fore.RESET}] Blacklisted?: {keyauthapp.checkblacklist()}")

subs = keyauthapp.user_data.subscriptions
for i in range(len(subs)):
    sub = subs[i]["subscription"]
    expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
        '%d-%m-%Y')
    timeleft = subs[i]["timeleft"]

#    print(f"[{Fore.LIGHTYELLOW_EX}%{Fore.RESET}] [{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")


#print(f"[{Fore.LIGHTMAGENTA_EX}%{Fore.RESET}] Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%d-%m-%Y %S:%M:%H'))
#print(f"[{Fore.LIGHTMAGENTA_EX}%{Fore.RESET}] Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%d-%m-%Y %S:%M:%H'))

proxycount = len(open('proxies.txt').readlines()) # proxy count (proxie.txt file)

#######################################


THIS_VERSION = "2.7.6" #v3.2.8

import os
import time
import json
import random
import string
import base64
import ctypes
import colorama
import requests
import threading
import http.client
import webbrowser, base64
from utils import TokenUtils
from colorama import init, Fore
from invisifox import InvisiFox
from twocaptcha import TwoCaptcha
from structures import ProxyPool, Proxy
from capmonster_python import HCaptchaTask
from anticaptchaofficial.hcaptchaproxyless import *

b = Fore.LIGHTBLUE_EX
p = Fore.LIGHTMAGENTA_EX
w = Fore.LIGHTWHITE_EX
r = Fore.LIGHTRED_EX
g = Fore.LIGHTGREEN_EX
ly = Fore.LIGHTYELLOW_EX
y = Fore.YELLOW

def clear_screen():
    os.system("clear")
    os.system("cls")
    return

os.system('cls')
if len(open("proxies.txt").read().splitlines()) == 0:
    print(f"\n[{Fore.LIGHTRED_EX}!{Fore.RESET}] You Have No Proxies in you're proxie.txt file! (Make Sure To Fill It Out Before Launching Again!)")
    sleep(2)
    print(f"[{Fore.LIGHTRED_EX}!{Fore.RESET}] Closing GANG GENERATOR in 5 Seconds...")
    sleep(5)
    exit()

os.system(f"title Check {proxycount} Proxies")
proxychecker = input(f"""
[{g}>{w}] Would You Like To Check Your Proxies? [Y/N]: """)

if proxychecker in ['y','Y','yes', 'ye']:
        with open('proxies.txt') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                print(line.strip())
            clear_screen()

elif proxychecker in ['n','N','no','nah']:
            pass
            clear_screen()
else:
        print('')
        clear_screen()

########################################

Version = "v1.0"
host_details = {
    "url" : "discord.com",
    "port" : 443 
}

blacklisted_IPS = []
IPS_in_use = []
auth_proxies = []
char_symbols = ["!", "@", "#", "$", "5"]

total_auth_proxies = 0
index_pos = 0
bot = InvisiFox()
proxy_recycle_message_sent = False

init(convert=True)
colorama.init(autoreset=True)

product = 'discord'
site_key = "4c672d35-0701-42b2-88c3-78380b0db560"
email_site_key = "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34"

########################################

with open("config.json") as config:
    config = json.load(config)
    anticaptcha_API = config["anticaptcha_api_key"]
    capmonster_API = config["capmonster_api_key"]
    twocaptcha_API = config['2captcha_API_key']
    InvisiFox_api_key = config['invisiFox_API_key']
    use_InvisiFox = config['use_InvisiFox']
    use_2captcha = config['use_2captcha']
    use_capmonster = config["use_capmonster"]
    if use_2captcha == True and use_capmonster == True or use_2captcha == True and use_InvisiFox == True or use_capmonster == True and use_InvisiFox == True:
        print(f"[{r}!{w}] You can only use 1 Captcha Provider please modify your config.json file!")
        time.sleep(5)
        exit(0)
    threadss = config['threads']
    password = config['password']
    birthday = config['Date_of_birth']
    show_proxy_errors = config['Display_proxy_errors']
    join_server = config['Join_Server_On_Creation']
    invite_link = config['Server_Invite']
    use_proxies_for_capmonster = config['capmonster_use_proxies']
    if_ip_auth = config['user:pass@ip:port format']
    hotmailbox_API_key = config['hotmailbox_API']
    use_hotmailbox = config['use_hotmailbox']
    gen_passwords = config['generate_password']
    fivesim_API = config["5sim_API"]
    use_5sim = config['use_5sim']
    country = config['5sim_country']
    operator = config['5sim_op']
    del config
bot.apiKey = InvisiFox_api_key
token_type = "OTz" # might need to change this to MTA / MTz
_5s_token = fivesim_API

os.system(f"title GANG-Nuker Token Generator  -  Proxies: [{proxycount}]  -  Threads: [{threadss}]")

########################################

if use_5sim == True and use_hotmailbox == True:
    token_type = "Email & Phone Verified Tokens"
elif use_5sim == True and use_hotmailbox == False:
    token_type = "Phone Verified Tokens"
elif use_5sim == False and use_hotmailbox == True:
    token_type = "Email Verified Tokens"
else:
    token_type = "Unverified Tokens"

########################################

def purchase_email():
    url = f"https://api.hotmailbox.me/mail/buy?apikey={hotmailbox_API_key}&mailcode=HOTMAIL&quantity=1"
    r = requests.get(url)
    data = r.json()
    email = data['Data']['Emails'][0]['Email']
    email_password = data['Data']['Emails'][0]['Password']
    return email, email_password

def auth_proxy_request(url, port, username, password, method, route, payload, headers):
    conn = http.client.HTTPSConnection(url, port)
    auth = '%s:%s' % (username, password)
    headers['Proxy-Authorization'] = 'Basic ' + str(base64.b64encode(auth.encode())).replace("b'", "").replace("'", "")
    conn.set_tunnel(host_details['url'], host_details['port'], headers)
    conn.request(method, route, payload, headers)
    return conn

def parse_ip_port_proxy(proxy):
    IP = proxy.split(":")[0].replace('\n', '')
    PORT = proxy.split(":")[1].replace('\n', '')
    return IP, PORT

with open("proxies.txt") as proxy:
    if if_ip_auth == False:
        proxies = ProxyPool(proxy.read().splitlines())
    else:
        proxies = proxy.read().splitlines()
        for proxy in proxies:
            auth_proxies.append(proxy)
            total_auth_proxies += 1

def solve_captcha(site_key, proxy=None):
    if capmonster_API != "" and use_capmonster == True:
        if use_proxies_for_capmonster == True and proxy != None:
            if if_ip_auth == False:
                ip, port = parse_ip_port_proxy(proxy)
                print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
                capmonster = HCaptchaTask(capmonster_API)
                try:
                    capmonster.set_proxy("http", ip, port)
                    task_id = capmonster.create_task("https://discord.com/register", site_key)
                    result = capmonster.join_task_result(task_id)
                    g_response = result.get("gRecaptchaResponse")
                    return g_response
                except Exception:
                    print(f"[ {y}>{w} ] This proxy Does not work with capmonster")
                    return ""
            else:
                ip_username, ip_password, ip_ip, ip_port = parse_auth_proxy(proxy)
                print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
                capmonster = HCaptchaTask(capmonster_API)
                try:
                    capmonster.set_proxy("http", ip_ip, ip_port, ip_username, ip_password)
                    task_id = capmonster.create_task("https://discord.com/register", site_key)
                    result = capmonster.join_task_result(task_id)
                    g_response = result.get("gRecaptchaResponse")
                    return g_response
                except Exception:
                    print("[!] this proxy does not work with capmonster!")
                    return ""
        else:
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            capmonster = HCaptchaTask(capmonster_API)
            task_id = capmonster.create_task("https://discord.com/register", site_key)
            result = capmonster.join_task_result(task_id)
            g_response = result.get("gRecaptchaResponse")
            return g_response

    elif use_2captcha == True:
        print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
        solver = TwoCaptcha(twocaptcha_API)
        try:
            result = solver.hcaptcha(
                sitekey=site_key,
                url='https://discord.com',
            )
        except Exception as e:
            print(e)
            print(f"[ {r}!{w} ] Solving Captcha ERROR")
            return ""
        else:
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            result = result.get("code")
            return result

    elif use_InvisiFox == True and proxy == None:
        print("To use InvisiFox as your Captcha provider you are required to pass in a proxy!")
        return "Error"
    elif use_InvisiFox == True and proxy != None:
    
        print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
        if if_ip_auth == True:
            try:
                solution = bot.solveHCaptcha(site_key, 'https://discord.com', f'http://{proxy}')
            except Exception as error:
                print("There was an error trying to solve captcha using InvisiFox!")
                time.sleep(0.1)
                return "error"
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            return solution
        else:
            try:
                solution = bot.solveHCaptcha(site_key, 'https://discord.com', proxy)
            except Exception as error:
                print(f"There was an error trying to solve captcha using InvisiFox! {error}")
                time.sleep(0.1)
                return "error"
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            return solution
    else:
        print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
        solver = hCaptchaProxyless()
        solver.set_verbose(1)
        solver.set_key(anticaptcha_API)
        solver.set_website_url("https://discord.com")
        solver.set_website_key(site_key)
        g_response = solver.solve_and_return_solution()
        if g_response != 0:
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            return g_response
        else:
            print(f"[ {y}+{w} ] Fetching Captcha {site_key}\n[ {y}+{w} ] Solving Captcha")
            return ""


def generate_username(length):
    username = ""
    for i in range(int(length)):
        letter = random.choice(string.ascii_lowercase)
        username += letter
    return username

def generate_email(length):
    domains = ["@ezztt.com", "@gmail.com"]
    domain = random.choice(domains)
    email = ""
    for i in range(int(length)):
        letter = random.choice(string.ascii_lowercase)
        email += letter
    email += domain
    return email

def get_fingerprint(proxy):
    if if_ip_auth == False:
        conn = proxy.get_connection("discord.com")
        conn.putrequest("GET", "/api/v9/experiments")
        conn.endheaders()
        response = conn.getresponse()
        response = response.read()
        fingerprint = json.loads(response)
        fingerprint = fingerprint['fingerprint']
        session = requests.Session()
        cookiess = session.get("https://discord.com") # might need to keep it as: [https://discord.com]
        cookiess = session.cookies.get_dict()
        dcfduid = cookiess.get("__dcfduid")
        sdcfduid = cookiess.get("__sdcfduid")
        return fingerprint, dcfduid, sdcfduid
    else:
        ip_username, ip_password, ip_ip, ip_port = parse_auth_proxy(proxy)
        proxy_details = {
            "url" : ip_ip, 
            "port" : ip_port, 
            "username" : ip_username, 
            "password" : ip_password 
        }
        headers = {}
        payload = {}
        try:
            conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "GET", "/api/v9/experiments", payload, headers)
        except http.client.RemoteDisconnected:
            print(f"[{y}>{w}] Auth Proxy Error")
            return None, None, None
        response = conn.getresponse()
        response = response.read()
        fingerprint = json.loads(response)
        fingerprint = fingerprint['fingerprint']
        session = requests.Session()
        cookiess = session.get("https://discord.com") # [STAR]
        cookiess = session.cookies.get_dict()
        dcfduid = cookiess.get("__dcfduid")
        sdcfduid = cookiess.get("__sdcfduid")
        return fingerprint, dcfduid, sdcfduid



def parse_auth_proxy(proxy):
    proxy = proxy.replace("@", ":")
    colons_hit = 0
    ip_username = ""
    ip_password = ""
    ip_ip = ""
    ip_port = ""
    for character in proxy:
        if character == ":":
            colons_hit = colons_hit + 1
        else:
            if colons_hit == 0:
                ip_username += character
            elif colons_hit == 1:
                ip_password += character
            elif colons_hit == 2:
                ip_ip += character
            elif colons_hit == 3:
                ip_port += character
    return ip_username, ip_password, ip_ip, ip_port


def verify_phone(proxy, discord_token, discord_password):
    if use_5sim == True:
        
        headers = {
            'Authorization': 'Bearer ' + _5s_token,
            'Accept': 'application/json',
        }
        response = requests.get('https://5sim.net/v1/user/buy/activation/' + country + '/' + operator + '/' + product, headers=headers)
        try:
            phone_number = response.json()['phone']
        except Exception as error:
            print(f"[ {g}+{w} ] Fetching FingerPrint From 5Sim")
            sleep(7)
            print(f"[ {g}+{w} ] Gettings Phone Number Verfication Code")
            sleep(13)
            print(f"[ {r}!{w} ] ERROR  |  This Could Be The Country / Operator / API Issue.")
            time.sleep(10)
            exit(0)
        phone_id = response.json()['id']
        try:
            phone_id_str = str(phone_id)
        except Exception as error:
            print(error)
        captcha_key = solve_captcha(email_site_key)
        if if_ip_auth == False:
            headers = {
                "authorization": discord_token,
                "content-type": "application/json",
                "cookie": "__dcfduid=156676b0e52511ecab049748e388ba01; __sdcfduid=156676b1e52511ecab049748e388ba016c54df50488a2d1e13423eba666addd5a3d24e93d46dddf02e471fa26e7d7b7a",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
            }
            payload = {
                "captcha_key": captcha_key,
                "change_phone_reason": "user_action_required",
                "phone": phone_number
            }
            payload = json.dumps(payload)
            conn = proxy.get_connection("discord.com")
            conn.request("POST", "/api/v9/users/@me/phone", payload, headers)
            response = conn.getresponse()
            if int(response.status) == 204:
                print(f"[ {g}${w} ] Sent Verification Code to Phone Number")
            else:
                print(f"[ {r}!{w} ] Could not send verification code to number!")
                return
            result = ""
            headers = {
                'Authorization': 'Bearer ' + _5s_token,
                'Accept': 'application/json',
            }
            Retrys = 0
            while result != "NULL":
                response = requests.get('https://5sim.net/v1/user/check/' + phone_id_str, headers=headers)
                data = response.json()
                result = data['status']
                try:
                    code = data['sms'][0]['code']
                    break
                except Exception as error:
                    Retrys += 1
                    if Retrys > 375:
                        print(f"[ {r}!{w} ] Could not find Verification Code from Discord!")
                        return
            headers = {
                "authorization": discord_token,
                "content-type": "application/json",
                "cookie": "__dcfduid=156676b0e52511ecab049748e388ba01; __sdcfduid=156676b1e52511ecab049748e388ba016c54df50488a2d1e13423eba666addd5a3d24e93d46dddf02e471fa26e7d7b7a",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
            }
            payload = {
                "code": code,
                "phone": phone_number
            }
            payload = json.dumps(payload)

        else:
            ip_username, ip_password, ip_ip, ip_port = parse_auth_proxy(proxy)
            proxy_details = {
                "url" : ip_ip, 
                "port" : ip_port, 
                "username" : ip_username, 
                "password" : ip_password 
            }
            headers = {
                "authorization": discord_token,
                "content-type": "application/json",
                "cookie": "__dcfduid=156676b0e52511ecab049748e388ba01; __sdcfduid=156676b1e52511ecab049748e388ba016c54df50488a2d1e13423eba666addd5a3d24e93d46dddf02e471fa26e7d7b7a",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
            }
            payload = {
                "captcha_key": captcha_key,
                "change_phone_reason": "user_action_required",
                "phone": phone_number
            }
            payload = json.dumps(payload)
            conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "POST", "/api/v9/users/@me/phone", payload, headers)
            response = conn.getresponse()
            if int(response.status) == 204:
                print(f"[ {g}${w} ] Sent Verification Code to Phone Number")
            else:
                print(f"[ {r}!{w} ] Could not send verification code to number!")
                return
            result = ""
            headers = {
                'Authorization': 'Bearer ' + _5s_token,
                'Accept': 'application/json',
            }
            Retrys = 0
            while result != "NULL":
                response = requests.get('https://5sim.net/v1/user/check/' + phone_id_str, headers=headers)
                data = response.json()
                result = data['status']
                try:
                    code = data['sms'][0]['code']
                    break
                except Exception as error:
                    Retrys += 1
                    if Retrys > 375:
                        print(f"[ {r}!{w} ] Could not find Verification Code from Discord!")
                        return
            headers = {
                "authorization": discord_token,
                "content-type": "application/json",
                "cookie": "__dcfduid=156676b0e52511ecab049748e388ba01; __sdcfduid=156676b1e52511ecab049748e388ba016c54df50488a2d1e13423eba666addd5a3d24e93d46dddf02e471fa26e7d7b7a",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
            }
            payload = {
                "code": code,
                "phone": phone_number
            }
            payload = json.dumps(payload)
            conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "POST", "/api/v9/phone-verifications/verify", payload, headers)
            response = conn.getresponse()
            if int(response.status) == 200:
                pass
            else:
                print(f"[ {r}#{w} ] Invalid Verification Code!")
                return
            response = response.read()
            verify_url_token = json.loads(response)
            verify_url_token = verify_url_token['token']
            headers = {
                "authorization": discord_token,
                "content-type": "application/json",
                "cookie": "__dcfduid=156676b0e52511ecab049748e388ba01; __sdcfduid=156676b1e52511ecab049748e388ba016c54df50488a2d1e13423eba666addd5a3d24e93d46dddf02e471fa26e7d7b7a",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
            }
            payload = {
                "change_phone_reason": "user_action_required",
                "password": discord_password,
                "phone_token": verify_url_token
            }
            payload = json.dumps(payload)
            conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "POST", "/api/v9/users/@me/phone", payload, headers)
            response = conn.getresponse()
            if int(response.status) == 204:
                print(f"[ {y}+{w} ] Phone Verified {discord_token}")
                return
            else:
                print(f"[ {r}%{w} ] Issue Verifying Response Code!")
                return
        return

def verify_email(token, username, password, proxy):
    url = f'https://getcode.hotmailbox.me/discord?email={username}&password={password}&timeout=50'
    data = requests.get(url)
    data = data.json()
    Verfication_Link = data['VerificationCode']
    Verfication_Link = Verfication_Link.replace("https://click.discord.com", "")
    if if_ip_auth == False:
        conn = proxy.get_connection("click.discord.com")
        headers = {}
        payload = {}
        Verfication_Link = Verfication_Link.replace("\r\n\r\n", "")
        Verfication_Link = Verfication_Link.replace("\r", "")
        conn.request("GET", Verfication_Link, payload, headers)
        response = conn.getresponse()
        headers = response.getheaders()
        ans = [val for key, val in headers if key == 'Location'][0]
        str_ans = str(ans)
        url_token = str_ans.replace("https://discord.com/verify#token=", "")
        ans = ans[19:]
        captcha_key = solve_captcha(email_site_key, proxy)
        fingerprint, dcfduid, sdcfduid = get_fingerprint(proxy)
        headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "cookie": f"__dcfduid={dcfduid}; __sdcfduid={sdcfduid}; locale=en-US",
            "origin": "https://discord.com",
            "referer": "https://discord.com/verify",
            "sec-ch-ua": '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-fingerprint": fingerprint,
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        }
        payload = {
            "captcha_key": captcha_key,
            "token": url_token
        }
        payload = json.dumps(payload)
        conn = proxy.get_connection("discord.com")
        conn.request("POST", "/api/v9/auth/verify", payload, headers)
        r1 = conn.getresponse()
        if int(r1.status) == 200:
            print(f"[ {g}+{w} ] Successfully Email Verified {g}{token[:63]}*********{w}")
            return
        else:
            print(f"[ {r}!{w} ] Failed to Verify Email!")
            return

    else:
        ip_username, ip_password, ip_ip, ip_port = parse_auth_proxy(proxy)
        proxy_details = {
            "url" : ip_ip, 
            "port" : ip_port, 
            "username" : ip_username, 
            "password" : ip_password 
        }

        headers = {}
        payload = {}
        conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "GET", Verfication_Link, payload, headers)
        response = conn.getresponse()
        response = response.getheaders()
        ans = [val for key, val in response if key == 'Location'][0]
        str_ans = str(ans)
        url_token = str_ans.replace("https://discord.com/verify#token=", "")
        ans = ans[19:]
        captcha_key = solve_captcha(email_site_key, proxy)
        fingerprint, dcfduid, sdcfduid = get_fingerprint(proxy)
        #https://gangnuker.org/
        headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json",
            "cookie": f"__dcfduid={dcfduid}; __sdcfduid={sdcfduid}; locale=en-US",
            "origin": "https://discord.com",
            "referer": "https://discord.com/verify",
            "sec-ch-ua": '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.33 Safari/537.36",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-fingerprint": fingerprint,
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMy4wLjUwNjAuMzMgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMy4wLjUwNjAuMzMiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        }
        payload = {
            "captcha_key": captcha_key,
            "token": url_token
        }
        payload = json.dumps(payload)
        conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "POST", "/api/v9/auth/verify", payload, headers)
        r1 = conn.getresponse()
        if int(r1.status) == 200:
            print(f"[ {y}+{w} ] Successfully Email Verified {g}{token[:63]}*********{w}")
            return
        else:
            print(f"[ {y}+{w} ] Failed to Verify Email!")
            return


def generate_passwords(length):
    length -= 2
    password = ""
    for i in range(length):
        letter = random.choice(string.ascii_lowercase)
        password += letter
    symbol1 = random.choice(char_symbols)
    symbol2 = random.choice(char_symbols)
    password += symbol1
    password += symbol2
    return password

def create_account(proxy):
    if proxy in IPS_in_use:
        return
    IPS_in_use.append(proxy)
    if if_ip_auth == True:
        ip_username, ip_password, ip_ip, ip_port = parse_auth_proxy(proxy)
    if gen_passwords == True:
        password = generate_passwords(random.randint(15, 19))
    fingerprint, dcfduid, sdcfduid = get_fingerprint(proxy)
    username = generate_username(random.randint(8, 12))
    email = generate_email(random.randint(9, 13))
    Captcha = solve_captcha(site_key, proxy)
    if use_hotmailbox == True:
        email, email_password = purchase_email()
    else:
        pass

    if if_ip_auth == False:
        conn = proxy.get_connection("discord.com")
        print(f"[ {y}+{w} ] Getting FingerPrint - {fingerprint}")
        sleep(1)
        print(f"[ {y}+{w} ] Creating Token")
        headers = {
            "origin": "https://discord.com/register",
            "referer": "https://discord.com/",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-fingerprint": fingerprint,
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMi4wLjUwMDUuNjEgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMi4wLjUwMDUuNjEiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwMTUzLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        }
        if join_server == True:
            if invite_link != "None":
                payload = {
                    "captcha_key": Captcha,
                    "consent": "true",
                    "date_of_birth": birthday,
                    "email": email,
                    "fingerprint": fingerprint,
                    "gift_code_sku_id": "null",
                    "invite": invite_link,
                    "password": password,
                    "username": username
                }
            else:
                print(f"[ {r}!{w} ] Joiner is ENABLED but you dont have a invite link in config.json!")
                return
        else:
            payload = {
                "captcha_key": Captcha,
                "consent": "true",
                "date_of_birth": birthday,
                "email": email,
                "fingerprint": fingerprint,
                "gift_code_sku_id": "null",
                "invite": "null",
                "password": password,
                "username": username
            }
        payload = json.dumps(payload)
        conn.request("POST", "/api/v10/auth/register", payload, headers)
        response = conn.getresponse()
        data = response.read().decode()
        if "token" not in str(data):
            print(f"[ {r}!{w} ] Email FingerPrint ERROR: [{r}{fingerprint}{w}]")
            return
        else:
            data = data.replace('{"token": "', '')
            data = data.replace('"}', '')
            token = data
            print(f"[ {g}+{w} ] Generated Token: | {token[:63]}*********{w}\n[ {g}+{w} ] Username: {g}{username}{w}  Password: {g}{password}{w}  Email: {g}{email}{w}")
            file = open("tokens.txt", "a+")
            file.write(f"{email}:{password}:{token}\n")
            file.close()
            if use_hotmailbox == True:
                print(f"[ {g}+{w} ] Attemping To Email Verify: {token[:63]}*********")
                sleep(4)
                print(f"[ {g}+{w} ] Getting Email Verification Code: {token[:63]}*********")
                verify_mail = verify_email(token, email, email_password, proxy)
            if use_5sim == True:
                print(f"[ {g}+{w} ] Attempting to Phone Verify {token[:63]}*********")
                res = verify_phone(proxy, token, password)
            else:
                return
            return
    else:
        proxy_details = {
            "url" : ip_ip, 
            "port" : ip_port, 
            "username" : ip_username, 
            "password" : ip_password 
        }
        
        payload = {
            "captcha_key": Captcha,
            "consent": "true",
            "date_of_birth": birthday,
            "email": email,
            "fingerprint": fingerprint,
            "gift_code_sku_id": "null",
            "invite": "null",
            "password": password,
            "username": username
        }
        headers = {
            
            "cookies": f"__dcfduid={dcfduid}; __sdcfduid={sdcfduid}",
            "origin": "https://discord.com",
            "referer": "https://discord.com/register",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-fingerprint": fingerprint,
            "x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMi4wLjUwMDUuNjEgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwMi4wLjUwMDUuNjEiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTMwMTUzLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        }
        payload = json.dumps(payload)
        try:
            conn = auth_proxy_request(proxy_details['url'], proxy_details['port'], proxy_details['username'], proxy_details['password'], "POST", "/api/v9/auth/register", payload, headers)
            response = conn.getresponse()
        except Exception:
            print("Proxy Remote end closed connection without response!")
            return
        data = response.read().decode()
        if "token" not in str(data):
            print(f"[ {r}!{w} ] Captcha Solver | Key Issue")
            return
        else:
            data = data.replace('{"token": "', '')
            data = data.replace('"}', '')
            token = data
            print(f"[ {g}+{w} ] Generated Token: | {token[:63]}*********{w}\n[ {g}+{w} ] Username: {g}{username}{w}  Password: {g}{password}{w}  Email: {g}{email}{w}")
            file = open("tokens.txt", "a+")
            file.write(f"{email}:{password}:{token}\n")
            file.close()
            if use_hotmailbox == True:
                print(f"[ {g}+{w} ] Attemping To Email Verify: {token[:63]}*********")
                sleep(4)
                print(f"[ {g}+{w} ] Getting Email Verification Code {token[:63]}*********")
                verify_mail = verify_email(token, email, email_password, proxy)
            if use_5sim == True:
                print(f"[ {y}+{w} ] Attempting to Phone Verify: {token[:63]}*********")
                res = verify_phone(proxy, token, password)
            else:
                return
            return

class Thread(threading.Thread):
    def run(self):
        global index_pos
        global proxy_recycle_message_sent
        while True:
            if if_ip_auth == False:
                try:
                    with next(proxies) as proxy:
                        proxy = proxy
                        if proxy in blacklisted_IPS:
                            print(f"[ {y}+{w} ] Skipping Proxy Because of Previous Connection Issues!")
                        generate_account = create_account(proxy)
                        return self.run()
                except Exception as err:
                    if show_proxy_errors == True:
                        print(f"[ {r}!{w} ] Weak/Dead Proxy: {err} ")
                    blacklisted_IPS.append(proxy)
            else:
                if index_pos == total_auth_proxies:
                    if proxy_recycle_message_sent == False:
                        print(f"[ {g}@{w} ] All Proxies Have Been Used, wait around 10 Minutes to Generate Again!")
                    proxy_recycle_message_sent = True
                    time.sleep(5)
                    index_pos = 0
                    return self.run()
                try:
                    proxy = auth_proxies[index_pos]
                except IndexError:
                    if proxy_recycle_message_sent == False:
                        print(f"[ {g}@{w} ] All Proxies Have Been Used, wait around 10 Minutes to Generate Again!")
                    proxy_recycle_message_sent = True
                    time.sleep(8)
                    index_pos = 0
                    return self.run()

                index_pos += 1
                generate_account = create_account(proxy)
                time.sleep(0.5)
                return self.run()

def main():
    print(f"[ {r}READ{w} ] {ly}USE PAID HTTP/HTTPS PROXIES FOR BETTER PERFORMANCE!")
    print(f"[ {r}READ{w} ] {ly}MAKE SURE YOU FILL OUT THE CONFIG.JSON TO PREVENT ISSUES!")
    print(f"[ {b}INFO{w} ] Generating Tokens Has Started\n\n")
    threads = [Thread() for _ in range(threadss)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        time.sleep(0)

def menu():
    clear_screen()
    print("")
    Write.Print(f"  ________   _  _______\n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f" / ___/ _ | / |/ / ___/\n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f"/ (_ / __ |/    / (_ /\n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f"\___/_/_|_/_/|_/\___/__  ___ __________  ___\n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f" / ___/ __/ |/ / __/ _ \/ _ /_  __/ __ \/ _ \ \n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f"/ (_ / _//    / _// , _/ __ |/ / / /_/ / , _/\n", Colors.cyan_to_blue, interval=0.000)
    Write.Print(f"\___/___/_/|_/___/_/|_/_/ |_/_/  \____/_/|_| \n", Colors.cyan_to_blue, interval=0.000)
    print(f"                                                                    [{b}WORKING{w}]:  {g}YES{w}\n                                                                    [{b}PURCHASE{w}]: gangnuker.org\n                                                                    [{b}PHONE / EMAIL VERIFIED TOKEN GENERATOR{w}]")
    print(f"\n[{b}MAIN{w}] 1 | Generate Tokens")
    print(f"[{b}MAIN{w}] 2 | Check Config File")
    print(f"[{b}MAIN{w}] 3 | Status")
    print(f"[{b}MAIN{w}] 4 | Credits")
    print(f"[{b}MAIN{w}] 5 | Exit\n")
    choice = input(f"[{b}>{w}] Choice?: ")
    choice = int(choice)


    if choice == 1:
        return main()
    
    elif choice == 2:
        print(f'[{r}READ{w}] MAKE SURE TO FILL OUT THE CONFIG.JSON FILE PROPERLY!\n[{r}READ{w}] API KEYS AND PROXIES WILL BE NEEDED!\n\n[{y}APIS{w}] Capmonster / Anti-captcha.com are great and cheap api keys to use!\n[{y}APIS{w}] looking for cheap proxies? visit webshare.io\n')
        print(f"\n\n[{b}INFO{w}] Threads Running: {threadss}")
        print(f"[{b}INFO{w}] 2Captcha API key: {twocaptcha_API}")
        print(f"[{b}INFO{w}] AntiCaptcha API key: {anticaptcha_API}")
        print(f"[{b}INFO{w}] CapMonster API key: {capmonster_API}")
        print(f"[{b}INFO{w}] InvisiFox API key: {InvisiFox_api_key}")
        print(f"[{b}INFO{w}] Hotmailbox API key: {hotmailbox_API_key}")
        print(f"[{b}INFO{w}] Use Hotmailbox API: {use_hotmailbox}\n")
        print(f"[{b}INFO{w}] Display Proxy Errors: {show_proxy_errors}\n")
        print(f"[{b}INFO{w}] 5sim API key: {fivesim_API}")
        print(f"[{b}INFO{w}] Use 5sim: {use_5sim}")
        input(f"\n[{b}>{w}] Press ENTER:")
        return menu()

    elif choice == 3:
        print(f"\n\n[ {w}Token Generator Working?:{w} ]")
        print(f"[{g}WORKING{w}]  <--")
        print(f"[{y}FIXING{w}]")
        print(f"[{r}PATCHED{w}]")

        print(f"\n\n[ {w}Proxy Support:{w} ]")
        print(f"[{g}HTTP/HTTPS ONLY{w}]  <--")
        print(f"[{r}SOCK4{w}]  x")
        print(f"[{r}SOCK5{w}]  x")
        sleep(3)
        input(f"\n[{b}>{w}] Press ENTER: ")
        return menu()

    elif choice == 4:
            print(f"[{g}+{w}] Made by ††#1792")
            sleep(0.5)
            webbrowser.open('https://gangnuker.org')
            return menu()

    elif choice == 5:
        sys.exit(0)

    elif choice == '':
        menu()

menu()
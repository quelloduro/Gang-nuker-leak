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

os.system('cls')
if len(open("tokens.txt").read().splitlines()) == 0:
    print(f"[{Fore.LIGHTRED_EX}!{Fore.RESET}] You Have No Tokens in you're token.txt file! (make sure to fill it out before launching again!)")
    sleep(2)
    print(f"[{Fore.LIGHTRED_EX}!{Fore.RESET}] Closing GANG JOINER in 5 Seconds...")
    sleep(5)
    exit()


from util.settings import *
cancel_key = "ctrl+x"


def vc():
        tokenlist = open("tokens.txt", "r").read().splitlines()
        channel = int(input("[\x1b[95m>\x1b[95m\x1B[37m] Voice Channel ID: "))
        server = int(input("[\x1b[95m>\x1b[95m\x1B[37m] Server ID: "))
        deaf = input("[\x1b[95m>\x1b[95m\x1B[37m] Defean: (y/n)? ")
        if deaf == "y":
          deaf = True
          if deaf == "n":
            deaf = False
        mute = input("[\x1b[95m>\x1b[95m\x1B[37m] Mute: (y/n)? ")
        if mute == "y":
          mute = True
          if mute == "n":
            mute = False
        stream = input("[\x1b[95m>\x1b[95m\x1B[37m] Stream: (y/n)? ")
        if stream == "y":
          stream = True
          if stream == "n":
            stream = False
        video = input("[\x1b[95m>\x1b[95m\x1B[37m] Video Cam: (y/n)? ")
        if video == "y":
          video = True
          if video == "n":
            video = False

        executor = ThreadPoolExecutor(max_workers=int(100000))
        def run(token):
          while True:
            ws = WebSocket()
            ws.connect("wss://gateway.discord.gg/?v=8&encoding=json")
            hello = loads(ws.recv())
            heartbeat_interval = hello['d']['heartbeat_interval']
            ws.send(dumps({"op": 2,"d": {"token": token,"properties": {"$os": "windows","$browser": "Discord","$device": "desktop"}}}))
            ws.send(dumps({"op": 4,"d": {"guild_id": server,"channel_id": channel,"self_mute": mute,"self_deaf": deaf, "self_stream?": stream, "self_video": video}}))
            ws.send(dumps({"op": 18,"d": {"type": "guild","guild_id": server,"channel_id": channel,"preferred_region": "singapore"}}))
            ws.send(dumps({"op": 1,"d": None}))
            sleep(0.1)

        i = 0
        for token in tokenlist:
          executor.submit(run, token)
          i+=1
        
#def replyspammer(token, channel_id, message_id, text, amount):
#    og_text = text
#    request = requests.Session()
#    headers = {'Authorization':token, 
#     'Content-Type':'application/json', 
#     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36'}
#    for x in range(int(amount)):
#        if 5 > 5:
#            pass
#        else:
#            payload = {'content':text, 
#             'tts':False}
#            payload['message_reference'] = {
#                "channel_id": channel_id,
#                "message_id": message_id
#            }
#            src = request.post(f"https://canary.discordapp.com/api/v6/channels/{channel_id}/messages", headers=headers, json=payload, timeout=10)
#        if src.status_code == 429:
#            try:
#                ratelimit = json.loads(src.content)
#                time.sleep(float(ratelimit['retry_after'] / 1000))
#            except:
#                pass
#
#        else:
#            if src.status_code == 401:
#                pass
#            else:
#                if src.status_code == 404:
#                    pass
#                else:
#                    if src.status_code == 403:
#                        pass

def main():
    clear()
    global cancel_key
    banner()


    choice = input(f'\n\n[{Fore.LIGHTMAGENTA_EX}>{r}] Choice? {r} ')

# start of code
    if choice == '1':
        voicecall = input("[\x1b[95m>\x1b[95m\x1B[37m] Make tokens connect to a vc while joining? [y/n]: ")
        if voicecall.lower() == 'y' or voicecall.lower() == 'yes':
            vc()
        if voicecall.lower() == 'n' or voicecall.lower() == 'no':
            pass
        
#        import threading
#        replys = input("[\x1b[95m>\x1b[95m\x1B[37m] Make token reply to a message once joined? [y/n]: ")
#        if replys.lower() == 'y' or replys.lower() == 'yes':
#            tokens = open('tokens.txt', 'r').read().splitlines()
#            channel_id = input('Channel ID: ')
#            message_id = input('Message ID: ')
#            text = input('Message: ')
#            amount = input('Amount of replies for each token: ')
#            amount = int(amount)
#            for token in tokens:
#                threading.Thread(target=replyspammer, args=(token, channel_id, message_id, text, amount)).start()
#        if replys.lower() == 'n' or replys.lower() == 'no':
#            pass

        colorama.init(autoreset=True)
        lest = []


        def join(token, invite):
            session = requests.session()
            try:
                session.headers["X-Fingerprint"] = session.get("https://discord.com/api/v9/experiments").json()["fingerprint"]
                rer = session.post("https://discord.com/api/v9/invites/"+invite, headers={"authorization": token})
                if "200" not in str(rer):
                    site = str(requests.get("https://pastebin.com/raw/GWnQeQ4v").text)
                    tt = cap.create_task("https://discord.com/api/v9/invites/"+invite, site)
                    lest.append(f"Fetching Captcha")
                    captcha = cap.join_task_result(tt)
                    captcha = captcha["gRecaptchaResponse"]
                    lest.append("Captcha Was Solved")
                    session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive','sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"','X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkzLjAuNDU3Ny42MyBTYWZhcmkvNTM3LjM2IEVkZy85My4wLjk2MS40NyIsImJyb3dzZXJfdmVyc2lvbiI6IjkzLjAuNDU3Ny42MyIsIm9zX3ZlcnNpb24iOiIxMCIsInJlZmVycmVyIjoiaHR0cHM6Ly9kaXNjb3JkLmNvbS9jaGFubmVscy81NTQxMjU3Nzc4MTg2MTU4NDQvODcwODgxOTEyMzQyODUxNTk1IiwicmVmZXJyaW5nX2RvbWFpbiI6ImRpc2NvcmQuY29tIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk3NTA3LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==','Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.47",'Content-Type': 'application/json', 'Authorization': 'undefined','Accept': '*/*', 'Origin': 'https://discord.com','Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors','Sec-Fetch-Dest': 'empty', 'Referer': 'https://discord.com/@me','X-Debug-Options': 'bugReporterEnabled','Accept-Encoding': 'gzip, deflate, br','Cookie': 'OptanonConsent=version=6.17.0; locale=th'}
                    rej = session.post("https://discord.com/api/v9/invites/"+invite, headers={"authorization": token}, json={
                        "captcha_key": captcha,
                        "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
                    })
                    if "200" in str(rej):
                        lest.append("Token Joined Successfully")
                    if "200" not in str(rej):
                        lest.append("Failed To Join With Token / Maybe An Expired Sitekey")
                else:
                    lest.append("Token Joined Successfully")
            except:
                lest.append("Failed To Join With Token")

        def we():
            global e
            if e == False:
                e = True
        import json
        e = False
        try:
            error = False
            jen = open("config.json", "r")
            jsen = json.load(jen)
            try:
                cap_key = jsen["capmonster_key"]
                cap = capmonster_python.HCaptchaTask(cap_key)
                bal = cap.get_balance()
                if str(bal) == "0" or str(bal) == "0.0":
                    error = True
                    we()
                    sys.stdout.write(colorama.Fore.RED + "> ")
                    print015("More Funds Then 0 Needed")
            except Exception as e:
                error = True
                we()
                sys.stdout.write(colorama.Fore.RED + "> ")
                print015("Invalid Capmonster Key")
    

            try:
                with open("tokens.txt", "r") as file:
                    tokens = file.readlines()
            except:
                error = True
                we()
                sys.stdout.write(colorama.Fore.RED + "> ")
                print015("Missing tokens.txt Path")

            if error == True:
                input("")
                exit()
        except Exception as e:
            while True:
                try:
                    sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}${Fore.RESET}] ")
                    print01("Enter Capmonster Key: ")
                    cap_key = input("")
                    cap = capmonster_python.HCaptchaTask(cap_key)
                    bal = cap.get_balance()
                    if str(bal) == "0" or str(bal) == "0.0":
                        sys.stdout.write(colorama.Fore.RED + "> ")
                        print015("More Funds Then 0 Needed")
                    else:
                        break   
                except Exception as e:
                    sys.stdout.write(colorama.Fore.RED + "> ")
                    print015("Invalid Capmonster Key")

            file = open("config.json", "a")
            file.truncate(0)
            file.write('{"capmonster_key": ')
            file.write(f'"{cap_key}"')
            file.write("}")
            file.close()
            sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}>{Fore.RESET}] ")
            print01("Saved Information So Its Easier To Use Next Time, Restart The Program")
            input("")
            exit()



        while True:
            sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}>{Fore.RESET}] ")
            print01(f"Example: [discord.gg/******]\n")
            sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}>{Fore.RESET}] ")
            print01(f"Invite Code: ")
            invite_code = input("")
            re1 = requests.get(f"https://discord.com/api/v9/invites/{invite_code}?with_counts=true&with_expiration=true")
            if "200" in str(re1):
                break
            print015("[!] Invalid Invite Or Rate Limited")




        import threading

        for token in tokens:
            if "\n" in token:
                token = token[:-1]
    
            threading.Thread(target=join, args=(token, invite_code,)).start()
            sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}+{Fore.RESET}] ")
            print("Fetching Invite Code")

        joined = 0

        while True:
            if len(tokens) == int(joined):
                break
            for u in lest:
                lest.remove(u)
                if "Joined" in u:
                    joined = int(joined) + 1
                if "Failed" not in u:
                    sys.stdout.write(f"[{Fore.LIGHTMAGENTA_EX}+{Fore.RESET}] ")
                    print(u)
                if "Failed" in u:
                    sys.stdout.write(f"[{Fore.RED}!{Fore.RESET}] ")
                    print(u)
        print("")

        sys.stdout.write(f"\n[{Fore.LIGHTMAGENTA_EX}>{Fore.RESET}] ")
        print01("Done, All Tokens Have Joined The Server!")
        input("")



# changer
    if choice == '2':
            exits = input(f'[{nr}!{Fore.RESET}] Are you sure you want to exit? (Y to confirm): {Fore.RED}')
            if exits.lower() == 'y' or exits.lower() == 'yes':
                clear()
                os._exit(0)
            else:
                main()
    else:
        clear()
        main()



if __name__ == "__main__":
    import sys
    if os.path.basename(sys.argv[0]).endswith("exe"):
        with open(getTempDir()+"\\hazard_proxies", 'w'): pass
        if not os.path.exists(getTempDir()+"\\hazard_theme"):
            ('opps')
        clear()
        sleep(1.5)
        main()
    try:
        assert sys.version_info >= (3,9)
    except AssertionError:
        print(f"{Fore.RED}Woopsie daisy, your python version ({sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}) is not compatible with opps, please download python 3.9+")
        sleep(5)
        print("exiting...")
        sleep(1.5)
        os._exit(0)
    else:
        with open(getTempDir()+"\\hazard_proxies", 'w'): pass
        if not os.path.exists(getTempDir()+"\\hazard_theme"):
            ('opps')
        clear()
        sleep(1.5)
        main()
    finally:
        Fore.RESET
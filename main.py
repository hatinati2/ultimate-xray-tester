import os
import json
import time
import requests
import subprocess
import sys
import base64
from urllib.parse import urlparse, unquote, parse_qs
import zipfile
import platform
import urllib.request
import winsound
import threading

# ------------------- مسیرهای محلی (همه چیز در همان فولدر اسکریپت) -------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
XRAY_DIR = os.path.join(SCRIPT_DIR, "xray_core")
LINKS_FILE = os.path.join(SCRIPT_DIR, "saved_links.txt")
XRAY_EXEC = "xray.exe" if platform.system() == "Windows" else "xray"
xray_path = os.path.join(XRAY_DIR, XRAY_EXEC)

# ------------------- صدای آلارم بسیار بلند و طولانی -------------------
def play_long_alarm():
    if platform.system() == "Windows":
        threading.Thread(target=lambda: [
            winsound.Beep(800, 600), winsound.Beep(1000, 600), winsound.Beep(1200, 600),
            winsound.Beep(1400, 800), winsound.Beep(1600, 800), winsound.Beep(1800, 1000),
            winsound.Beep(2000, 1200), winsound.Beep(2200, 1500), winsound.Beep(2400, 2000)
        ] * 15, daemon=True).start()

# ------------------- Auto-download Xray Core -------------------
if not os.path.exists(XRAY_DIR):
    os.makedirs(XRAY_DIR)

if not os.path.exists(xray_path):
    print("Downloading Xray Core... (only the first time)")
    system = platform.system()
    arch = platform.machine()

    if system == "Linux":
        if "arm" in arch or "aarch" in arch:
            url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"
        else:
            url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    elif system == "Windows":
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
    elif system == "Darwin":
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-64.zip"
    else:
        print("Unsupported operating system.")
        sys.exit(1)

    zip_path = os.path.join(XRAY_DIR, "xray.zip")
    urllib.request.urlretrieve(url, zip_path)
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(XRAY_DIR)
    
    os.remove(zip_path)
    print("Xray downloaded and ready!")

# ------------------- Parse any link (vmess/vless/trojan with Reality) -------------------
def parse_any_link(link):
    link = link.strip()
    if link.startswith("vmess://"):
        padded = link[8:] + '=' * ((4 - len(link[8:]) % 4) % 4)
        data = json.loads(base64.b64decode(padded).decode())
        return {
            "type": "vmess",
            "name": data.get("ps", "Vmess Config"),
            "add": data.get("add"),
            "port": int(data.get("port", 443)),
            "id": data.get("id"),
            "aid": int(data.get("aid", 0)),
            "net": data.get("net", "tcp"),
            "tls": data.get("tls", "none"),
            "host": data.get("host", ""),
            "path": data.get("path", "/"),
            "scy": data.get("scy", "auto")
        }
    elif link.startswith("vless://"):
        parsed = urlparse(link)
        uuid = parsed.username
        add = parsed.hostname
        port = parsed.port or 443
        query = parse_qs(parsed.query)
        get = lambda k, d="": unquote(query.get(k, [d])[0])
        
        security = get("security", "none")
        fp = get("fp", "chrome")
        sni = get("sni") or get("host") or add
        pbk = get("pbk", "")
        sid = get("sid", "")
        
        return {
            "type": "vless",
            "name": get("remark", f"Vless {add}") or link[:30],
            "add": add,
            "port": port,
            "id": uuid,
            "encryption": get("encryption", "none"),
            "flow": get("flow", ""),
            "network": get("type", "tcp"),
            "security": security,
            "fp": fp,
            "sni": sni,
            "pbk": pbk,
            "sid": sid,
            "path": get("path", "/"),
            "host": get("host", "")
        }
    else:
        return {"type": "unknown", "name": "Unsupported"}

# ------------------- Build outbound config -------------------
def build_outbound(info):
    if info["type"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": info["add"],
                    "port": info["port"],
                    "users": [{"id": info["id"], "alterId": info["aid"], "security": info["scy"]}]
                }]
            },
            "streamSettings": {
                "network": info["net"],
                "security": info["tls"]
            }
        }
        if info["net"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {"path": info["path"], "headers": {"Host": info["host"]}}
        if info["tls"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {}
        return outbound
    
    elif info["type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": info["add"],
                    "port": info["port"],
                    "users": [{"id": info["id"], "encryption": info["encryption"], "flow": info["flow"]}]
                }]
            },
            "streamSettings": {
                "network": info["network"],
                "security": info["security"]
            }
        }
        if info["security"] in ["tls", "reality"]:
            settings_key = "realitySettings" if info["security"] == "reality" else "tlsSettings"
            outbound["streamSettings"][settings_key] = {
                "serverName": info["sni"],
                "fingerprint": info["fp"]
            }
            if info["security"] == "reality":
                outbound["streamSettings"][settings_key].update({
                    "publicKey": info["pbk"],
                    "shortId": info["sid"]
                })
        if info["network"] == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": info["path"],
                "headers": {"Host": info["host"]}
            }
        return outbound
    
    return {"protocol": "freedom"}

# ------------------- Test connection with DELAY & RESPONSE TIME -------------------
def test_connection(port):
    proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
    try:
        start = time.time()
        r = requests.get("https://api.ipify.org", proxies=proxies, timeout=35)
        response_time = int((time.time() - start) * 1000)
        if r.status_code == 200:
            # محاسبه پینگ واقعی به گوگل (TCP delay)
            ping_start = time.time()
            google = requests.get("https://google.com", proxies=proxies, timeout=10)
            tcp_delay = int((time.time() - ping_start) * 1000)
            return True, r.text.strip(), tcp_delay, response_time
    except:
        pass
    return False, None, None, None

# ------------------- Tester Class -------------------
class ConfigTester:
    def __init__(self, link, index):
        self.info = parse_any_link(link)
        self.name = self.info.get("name", f"Config {index+1}")
        self.process = None
        self.port = 10810 + index
        self.connected = False
        self.last_ip = ""
        self.tcp_delay = 0
        self.response_time = 0
        self.was_connected = False

    def start(self):
        outbound = build_outbound(self.info)
        config = {
            "inbounds": [{"port": self.port - 1000, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
        }
        config_path = os.path.join(SCRIPT_DIR, f"config_{self.port}.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        cmd = [xray_path, "run", "-c", config_path]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)

    def check(self):
        connected, ip, tcp_delay, response_time = test_connection(self.port - 1000)
        self.connected = connected
        self.last_ip = ip or ""
        self.tcp_delay = tcp_delay or 0
        self.response_time = response_time or 0

        # آلارم فوری به محض قطع شدن هر کانفیگ
        if self.was_connected and not connected:
            print(f"\a\a\a  ⚡⚡⚡ DISCONNECTED: {self.name} ⚡⚡⚡")
            play_long_alarm()

        self.was_connected = connected
        return connected

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.kill()
            except:
                pass

# ------------------- ذخیره و بارگذاری لینک‌ها -------------------
def save_links(links):
    with open(LINKS_FILE, "w", encoding="utf-8") as f:
        for link in links:
            f.write(link.strip() + "\n")
    print(f"\nLinks saved automatically: {LINKS_FILE}")

def load_saved_links():
    if os.path.exists(LINKS_FILE):
        with open(LINKS_FILE, "r", encoding="utf-8") as f:
            saved = [line.strip() for line in f if line.strip()]
        if saved:
            print(f"{len(saved)} saved link(s) loaded automatically!\n")
            return saved
    return None

# ------------------- Main -------------------
print("="*70)
print("     Ultimate VPN Tester - VLESS Reality + AUTO SAVE + INSTANT LOUD ALARM")
print("            TCP Delay + Response Time + Long Alarm on Drop")
print("="*70)

links = load_saved_links()

if not links:
    while True:
        try:
            num_links = int(input("\nHow many links do you want to add? (1-10): ").strip())
            if 1 <= num_links <= 10:
                break
        except:
            pass

    links = []
    print(f"\nEnter your {num_links} link(s):\n")
    for i in range(num_links):
        while True:
            link = input(f"Link {i+1}/{num_links}: ").strip()
            info = parse_any_link(link)
            if info["type"] != "unknown":
                links.append(link)
                print(f"   ✓ Added: {info['name']} ({info['type'].upper()})")
                break
            else:
                print("   ✗ Invalid link. Try again.")
    save_links(links)
else:
    print("To change links → delete 'saved_links.txt' and run again.\n")

while True:
    try:
        interval = int(input("Check interval in seconds (5-60, default 15): ") or "15")
        if interval >= 5:
            break
    except:
        interval = 15

testers = [ConfigTester(l, i) for i, l in enumerate(links)]

print("\nStarting all configs...")
for t in testers:
    t.start()

print(f"\nChecking every {interval}s | INSTANT VERY LOUD ALARM ON ANY DROP")
print("Press Ctrl+C to stop.\n")
print("-"*80)

try:
    while True:
        print(f"[{time.strftime('%H:%M:%S')}] Status Check:")
        any_connected = False
        for t in testers:
            if t.check():
                delay_text = f"TCP Delay: {t.tcp_delay}ms" if t.tcp_delay else "Measuring..."
                print(f"  ✅ {t.name} | IP: {t.last_ip} | {delay_text} | Response: {t.response_time}ms")
                any_connected = True
            else:
                print(f"  ❌ {t.name} → DISCONNECTED")
        
        print("  " + "🌐 At least one connected!" if any_connected else "  💀 ALL DEAD!")
        print("-"*80)
        time.sleep(interval)

except KeyboardInterrupt:
    print("\nStopping all processes...")
    for t in testers:
        t.stop()
    print("All stopped. See you!")

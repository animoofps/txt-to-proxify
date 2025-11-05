#!/usr/bin/env python3
import os
import requests
import xml.etree.ElementTree as ET

# === Configuration ===
API_KEY = os.getenv("PROXYCHECK_API_KEY")   # API key fetched from environment variable
SOURCE_URL = "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
OUTPUT_FILE = "proxy_profile.ppx"
TEST_URL = "https://www.google.com/"
TIMEOUT = 30  # seconds per proxy test
MAX_GOOD = 5  # stop once we find this many working proxies

PROFILE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxifierProfile version="101" platform="Windows" product_id="0" product_minver="310">
  <Options>
    <Resolve>
      <AutoModeDetection enabled="true"/>
      <ViaProxy enabled="false"/>
      <TryLocalDnsFirst enabled="false"/>
    </Resolve>
    <Encryption mode="basic"/>
    <HttpProxiesSupport enabled="false"/>
    <HandleDirectConnections enabled="true"/>
    <ConnectionLoopDetection enabled="true"/>
    <ProcessServices enabled="true"/>
    <ProcessOtherUsers enabled="true"/>
  </Options>
  <ProxyList>
    {proxy_entries}
  </ProxyList>
  <ChainList/>
  <RuleList>
    <Rule enabled="true">
      <Name>Default</Name>
      <Action type="Proxy">{first_proxy_id}</Action>
    </Rule>
  </RuleList>
</ProxifierProfile>
"""

def fetch_proxy_list(url):
    resp = requests.get(url, timeout=TIMEOUT)
    resp.raise_for_status()
    lines = resp.text.splitlines()
    proxies = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        ip = parts[0]
        port = parts[1]
        proxies.append((ip, port))
    print(f"Fetched {len(proxies)} proxies from source.")
    return proxies

def check_ips_proxycheck(ips):
    url = "https://proxycheck.io/v3/"
    params = {
        "key": API_KEY,
        "vpn": 1,
        "risk": 1
    }
    data = {
        "ips": ",".join(ips)
    }
    try:
        resp = requests.post(url, params=params, data=data, timeout=TIMEOUT)
        resp.raise_for_status()
        result = resp.json()
    except Exception as e:
        print("ProxyCheck API error:", e)
        return []
    good_ips = []
    for ip, info in result.items():
        if ip == "status":
            continue

        # If info is dict:
        if isinstance(info, dict):
            proxy_flag = info.get("proxy", False)
            hosting_flag = info.get("hosting", False)
            # If they are strings, convert:
            if isinstance(proxy_flag, str):
                proxy_flag = proxy_flag.lower() == "yes"
            if isinstance(hosting_flag, str):
                hosting_flag = hosting_flag.lower() == "yes"
            if not proxy_flag and not hosting_flag:
                good_ips.append(ip)
        else:
            # If info is simple type: int, bool, or str
            # We treat non‑proxy only if it clearly says “no” or False
            if isinstance(info, bool):
                if info is False:
                    good_ips.append(ip)
            else:
                # string or number: convert to str and check
                if str(info).lower() in ("no", "false", "0"):
                    good_ips.append(ip)
    print(f"{len(good_ips)} IPs passed ProxyCheck filter.")
    return good_ips

def test_proxy(ip, port):
    proxy_url = f"socks5://{ip}:{port}"
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }
    try:
        resp = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        if resp.status_code == 200:
            return True
    except Exception:
        pass
    return False

def build_proxy_entries(proxies):
    entries = []
    for idx, (ip, port) in enumerate(proxies, start=100):
        entry = (f"""<Proxy id="{idx}" type="SOCKS5">
      <Address>{ip}</Address>
      <Port>{port}</Port>
      <Options>48</Options>
    </Proxy>""")
        entries.append(entry)
    return "\n    ".join(entries)

def write_profile(proxies):
    entries_xml = build_proxy_entries(proxies)
    first_id = 100 if proxies else 100
    content = PROFILE_TEMPLATE.format(proxy_entries=entries_xml, first_proxy_id=first_id)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {len(proxies)} working proxies to {OUTPUT_FILE}")

def main():
    proxies = fetch_proxy_list(SOURCE_URL)
    ip_list = [ip for (ip, port) in proxies]
    filtered_ips = check_ips_proxycheck(ip_list[:500])  # limit for API
    good = []
    for ip, port in proxies:
        if len(good) >= MAX_GOOD:
            break
        if ip not in filtered_ips:
            continue
        print(f"Testing proxy {ip}:{port} …", end="", flush=True)
        if test_proxy(ip, port):
            print(" SUCCESS")
            good.append((ip, port))
        else:
            print(" FAIL")
    if not good:
        print("No working proxies found – aborting.")
        return
    write_profile(good)
    print("Done.")

if __name__ == "__main__":
    main()



#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET

# Configuration
SOURCE_URL = "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
OUTPUT_FILE = "proxy_profile.ppx"
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
    resp = requests.get(url)
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
    return proxies

def build_proxy_entries(proxies):
    entries = []
    for idx, (ip, port) in enumerate(proxies, start=100):
        entry = f"""<Proxy id="{idx}" type="SOCKS5">
      <Address>{ip}</Address>
      <Port>{port}</Port>
      <Options>48</Options>
    </Proxy>"""
        entries.append(entry)
    return "\n    ".join(entries)

def write_profile(proxies):
    entries_xml = build_proxy_entries(proxies)
    first_id = 100 if proxies else 100
    content = PROFILE_TEMPLATE.format(proxy_entries=entries_xml, first_proxy_id=first_id)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {len(proxies)} proxies to {OUTPUT_FILE}")

def main():
    proxies = fetch_proxy_list(SOURCE_URL)
    if not proxies:
        print("No proxies found – aborting.")
        return
    write_profile(proxies)

if __name__ == "__main__":
    main()


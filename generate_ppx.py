#!/usr/bin/env python3
import os
import requests
import xml.etree.ElementTree as ET

# === Configuration ===
API_KEY = os.getenv("PROXYCHECK_API_KEY")   # API key fetched from environment variable
SOURCE_URL = "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
OUTPUT_FILE = "proxy_profile.ppx"
TEST_URL = "https://www.google.com/"
TIMEOUT = 15  # seconds per proxy test
MAX_GOOD = 100  # stop once we find this many working proxies

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
    {proxy_entri_

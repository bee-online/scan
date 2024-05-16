import os
import socket
import subprocess
import platform
from scapy.all import ARP, Ether, srp

print("Starting network scan...")

# Task 1: Scan all devices on the network
def scan_network():
    print("Scanning network for devices...")
    ip_range = "192.168.1.0/24"  # Change this to your network range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print(f"Found {len(devices)} devices on the network.")
    return devices

# Task 2: Get OS, version, kernel, and build version
def get_os_info(ip):
    print(f"Gathering OS information for {ip}...")
    try:
        output = subprocess.check_output(["nmap", "-O", ip])
        output = output.decode("utf-8")
        os_info = {}
        for line in output.split("\n"):
            if "OS:" in line:
                os_info['os'] = line.split(" ")[1]
            elif "Version:" in line:
                os_info['version'] = line.split(" ")[1]
            elif "Kernel:" in line:
                os_info['kernel'] = line.split(" ")[1]
            elif "Build:" in line:
                os_info['build'] = line.split(" ")[1]
        print(f"OS information gathered for {ip}: {os_info}")
        return os_info
    except:
        print(f"Failed to gather OS information for {ip}")
        return {}

# Task 3: Suggest exploitation methods
def suggest_exploitation(ip, os_info):
    print(f"Checking for vulnerabilities on {ip}...")
    vulnerabilities = []
    if os_info.get('os') == "Windows":
        if os_info.get('version') == "10":
            if os_info.get('build') == "19041":
                vulnerabilities.append("CVE-2020-0796: Windows 10 Remote Desktop Gateway RCE")
        elif os_info.get('version') == "7":
            if os_info.get('build') == "7601":
                vulnerabilities.append("CVE-2019-0708: Windows 7 Remote Desktop RCE")
    elif os_info.get('os') == "Linux":
        if os_info.get('kernel') == "5.10.0-8-amd64":
            vulnerabilities.append("CVE-2022-0185: Linux Kernel Heap Overflow")
    if vulnerabilities:
        print(f"Vulnerabilities found on {ip}: {', '.join(vulnerabilities)}")
    else:
        print(f"No vulnerabilities found on {ip}")
    return vulnerabilities

# Main script
devices = scan_network()
for device in devices:
    ip = device['ip']
    mac = device['mac']
    print(f"Processing device {ip} ({mac})...")
    os_info = get_os_info(ip)
    if os_info:
        suggest_exploitation(ip, os_info)
    else:
        print(f"Skipping device {ip} ({mac}) due to lack of OS information.")

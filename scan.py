import subprocess
import re
import os
import threading

def print_logo():
    logo = """
  ____                  
 / ___|  ___ __ _ _ __  
 \___ \ / __/ _` | '_ \ 
  ___) | (_| (_| | | | |
 |____/ \___\__,_|_| |_| 
    
    This script is built with love by Bee-Online 🐝
    """

    print(logo)

def run_netdiscover():
    print("Running netdiscover... (press 's' to stop)\n")
    process = subprocess.Popen(['netdiscover', '-P'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = []
    
    def read_output():
        while True:
            line = process.stdout.readline()
            if line == b'' and process.poll() is not None:
                break
            if line:
                decoded_line = line.decode().strip()
                output.append(decoded_line)
                if re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})", decoded_line):
                    print(decoded_line)
    
    thread = threading.Thread(target=read_output)
    thread.start()
    
    while thread.is_alive():
        user_input = input()
        if user_input.lower() == 's':
            process.terminate()
            break
    
    thread.join()
    return '\n'.join(output)

def parse_netdiscover_output(output):
    pattern = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})", re.MULTILINE)
    return pattern.findall(output)

def run_nmap(target_ip):
    print(f"Running nmap on {target_ip}... (press 's' to stop)\n")
    process = subprocess.Popen(['nmap', '-sV', '-O', '--script=vuln', target_ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = []
    
    def read_output():
        while True:
            line = process.stdout.readline()
            if line == b'' and process.poll() is not None:
                break
            if line:
                decoded_line = line.decode().strip()
                output.append(decoded_line)
                print(decoded_line)
    
    thread = threading.Thread(target=read_output)
    thread.start()
    
    while thread.is_alive():
        user_input = input()
        if user_input.lower() == 's':
            process.terminate()
            break
    
    thread.join()
    return '\n'.join(output)

def select_vulnerability(vuln_list):
    print("Select a vulnerability to exploit:")
    for i, vuln in enumerate(vuln_list):
        print(f"{i + 1}: {vuln}")
    choice = int(input("Enter the number of your choice: "))
    return vuln_list[choice - 1]

def run_metasploit(vuln):
    os.system('clear')
    print(f"Exploiting vulnerability: {vuln} using Metasploit...")
    os.system(f'msfconsole -q -x "search {vuln};"')

def main():
    print_logo()

    # Run netdiscover and get the results
    netdiscover_output = run_netdiscover()
    devices = parse_netdiscover_output(netdiscover_output)
    
    if not devices:
        print("No devices found.")
        return
    
    print("\nAvailable devices:")
    for i, device in enumerate(devices):
        print(f"{i + 1}: IP: {device[0]}, MAC: {device[1]}")

    # Select a target from the list
    choice = int(input("\nSelect a target by number: "))
    target_ip = devices[choice - 1][0]

    # Run nmap on the selected target
    nmap_output = run_nmap(target_ip)
    print(nmap_output)

    # Extract vulnerabilities from nmap output
    vuln_list = re.findall(r"VULNERABLE:\s+(.+)", nmap_output)
    
    if not vuln_list:
        print("No vulnerabilities found.")
        return
    
    # Select a vulnerability to exploit
    selected_vuln = select_vulnerability(vuln_list)

    # Run Metasploit to exploit the selected vulnerability
    run_metasploit(selected_vuln)

if __name__ == "__main__":
    main()

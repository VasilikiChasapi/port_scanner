import re
from scapy.all import *
from scapy.layers.inet import IP, TCP

try:
    host = input("Enter target host (IP address or domain name): ")
    p = list(input("Enter target ports to scan: ").split(","))
    temp = map(int, p)
    ports = list(temp)
    
    if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)):
        print("\n\nScanning...")
        print("Host: " + host)
        print("Ports: " + str(ports) + "\n")
        
        ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),verbose=0,timeout=2)
        for (s,r) in ans:
            print("[+] {} Open".format(s[TCP].dport))
        
except (ValueError, RuntimeError, TypeError, NameError):
    print("[-] Some Error Occured")
    print("[-] Exiting...")
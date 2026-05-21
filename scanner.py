import os
import sys
import socket
import platform
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1

def get_operating_system_by_ttl(ttl):
    """A classic networking trick to guess the OS based on ICMP TTL response."""
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Solaris/Cisco"
    return "Unknown"

def scan_network(target_ip_range):
    print(f"[*] Starting network scan on target range: {target_ip_range}")
    print(f"[*] Running platform detected: {platform.system()} ({platform.release()})")
    
    # 1. Craft an ARP Broadcast Request Packet
    # Ether(dst="ff:ff:ff:ff:ff:ff") broadcasts the packet to all devices in the network segment
    arp_request = ARP(pdst=target_ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = broadcast / arp_request

    # 2. Send the packet out and catch responses
    try:
        answered_list = srp(arp_request_packet, timeout=2, verbose=False)[0]
    except PermissionError:
        print("[!] CRITICAL ERROR: Network scanning requires administrative/root privileges!")
        sys.exit(1)

    discovered_devices = []

    # 3. Parse through responsive devices
    for element in answered_list:
        ip_address = element[1].psrc
        mac_address = element[1].hwsrc
        
        # Resolve Hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "Unknown Hostname"

        # Guess OS via an ICMP Ping TTL check
        os_guess = "Unknown"
        ping_packet = IP(dst=ip_address) / ICMP()
        reply = sr1(ping_packet, timeout=1, verbose=False)
        if reply:
            os_guess = get_operating_system_by_ttl(reply.ttl)

        device_info = {
            "ip": ip_address,
            "mac": mac_address,
            "hostname": hostname,
            "os": os_guess
        }
        discovered_devices.append(device_info)

    # Display results
    print("\n" + "="*70)
    print(f"{'IP Address':<16}{'MAC Address':<20}{'Hostname':<22}{'Estimated OS'}")
    print("="*70)
    for device in discovered_devices:
        print(f"{device['ip']:<16}{device['mac']:<20}{device['hostname']:<22}{device['os']}")
    print("="*70 + "\n")
    
    return discovered_devices

if __name__ == "__main__":
    # If a custom IP range is passed, use it, otherwise use a safe loopback range for testing
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    scan_network(target)
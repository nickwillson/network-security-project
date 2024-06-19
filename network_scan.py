from scapy.all import ARP, Ether, srp
import nmap

def scan_network(ip_range):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and receive responses
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')  # Scan ports 1-1024
    return nm[ip]

def main():
    ip_range = input("Enter the IP range for network scan (e.g., 192.168.1.1/24): ")
    print(f"Scanning network range: {ip_range}")
    devices = scan_network(ip_range)

    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
        scan_result = scan_ports(device['ip'])
        for proto in scan_result.all_protocols():
            print(f"  Protocol: {proto}")
            lport = scan_result[proto].keys()
            for port in lport:
                print(f"  Port: {port}, State: {scan_result[proto][port]['state']}")

if __name__ == "__main__":
    main()

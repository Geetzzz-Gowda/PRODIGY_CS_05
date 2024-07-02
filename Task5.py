#Network Packet Analyzer

import scapy.all as scapy

def sniff_packets(interface):
    print("[+] Sniffing packets on interface {}".format(interface))
    scapy.sniff(iface=interface, prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print("\n[+] Packet Captured:")
        print("    Source IP: {}".format(source_ip))
        print("    Destination IP: {}".format(destination_ip))
        print("    Protocol: {}".format(protocol))

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print("    Payload: {}".format(payload))

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")
    sniff_packets(interface)

if __name__ == "__main__":
    main()

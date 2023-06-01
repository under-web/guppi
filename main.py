import netifaces
from scapy.all import sniff
import netifaces as ni
import socket

def get_default_interface():
    interfaces = ni.interfaces()
    for interface in interfaces:
        print(interface)

def resolve_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return None

def packet_callback(packet):
    if 'IP' in packet:
        ip = packet['IP'].src
        if not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.16.'):
            domain = resolve_domain(ip)
            if domain is not None:
                print(f"IP: {ip}, Domain: {domain}")

get_default_interface()
sniff(iface='wlp2s0', prn=packet_callback, store=False)


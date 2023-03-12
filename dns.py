from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
import getmac


domain_ip = "127.0.0.2"
global_client_mac = getmac.get_mac_address()
global_mac_broadcast = "ff:ff:ff:ff:ff:ff"


def dns_server(packet):
    if DNSQR in packet and packet[UDP].dport == 53:
        if packet[DNSQR].qname.decode() == "www.ravidyoni.com.":
            print(f"DNS Query from {packet[IP].src} for {packet[DNSQR].qname.decode()}")
            ip = IP(dst=packet[IP].src, src=packet[IP].dst)
            udp = UDP(dport=packet[UDP].sport, sport=53)
            dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd)
            dns_resp = DNSRR(rrname=packet[DNSQR].qname, rdata=domain_ip)
            dns_an = DNSRR(rrname="www.ravidyoni.com", rdata=domain_ip)
            dns.nscount = 1
            dns.ns = dns_resp
            dns.arcount = 1
            dns.ar = dns_an
            response = ip / udp / dns
            send(response)
            print("[+]dns response packet sent")
        else:
            print("received another packet")


def start_dns_server():
    print("[+]listening for dns request packet")
    sniff(filter="udp and dst port 53", prn=dns_server)


if __name__ == '__main__':
    start_dns_server()

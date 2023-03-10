from scapy.all import *
from scapy.layers.dns import *

domain_ip = "127.0.0.1"
def dns_server(packet):
    if DNSQR in packet and packet[UDP].sport == 1234:
        print(f"DNS Query from {packet[IP].src} for {packet[DNSQR].qname.decode()}")
        print(packet[IP].src)
        ip = IP(dst=packet[IP].src, src=packet[IP].dst)
        udp = UDP(dport=packet[UDP].sport, sport=53)
        dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd)
        dns_resp = DNSRR(rrname=packet[DNSQR].qname, rdata=domain_ip)
        dns_an = DNSRR(rrname="www.example.com", rdata=domain_ip)
        dns.nscount = 1
        dns.ns = dns_resp
        dns.arcount = 1
        dns.ar = dns_an
        response = ip / udp / dns
        send(response)
        print("[+]response dns packet sent")


def start_dns_server():
    print("[+]listening for dns request packet")
    sniff(filter="udp and src port 1234", prn=dns_server)


if __name__ == '__main__':
    start_dns_server()

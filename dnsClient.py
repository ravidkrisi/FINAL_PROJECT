from scapy.all import *
from scapy.layers.dns import *

dns_query = DNSQR(qname="example.com", qtype="A")
ip = IP(dst="10.0.0.1", src="10.0.0.2")
udp = UDP(dport=53, sport=12345)
dns = DNS(id=1234, qr=0, qd=dns_query)
dns_req = ip / udp / dns
response = sr1(dns_req)
print(response[DNSRR].rdata)

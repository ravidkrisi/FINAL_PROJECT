from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import getmac
import time

# define dhcp server mac address and IP
dhcp_server_mac = getmac.get_mac_address()  # get local mac address
dhcp_server_ip = "10.0.0.1"

# define global variables
global_client_mac = getmac.get_mac_address()
global_client_ip = ""
global_dns_server = "10.0.0.2"
global_mac_broadcast = "ff:ff:ff:ff:ff:ff"


def generate_ip():
    global global_client_ip
    global_client_ip = "10.0.0.15"


def handle_discover_packet(packet):
    print("[+]received discover packet")
    # create offer packet
    ether = Ether(dst=global_mac_broadcast)
    ip = IP(src=dhcp_server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    generate_ip()  # generate client's IP
    boot_p = BOOTP(op=2, yiaddr=global_client_ip, siaddr=dhcp_server_ip, chaddr=global_client_mac, xid=1234)
    dhcp = DHCP(options=[("message-type", "offer"),
                         ("name_server", global_dns_server),
                         "end"])
    offer_packet = ether/ip/udp/boot_p/dhcp
    # send offer packet to client
    time.sleep(2)
    sendp(offer_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]offer packet sent")


def handle_request_packet(packet):
    print("[+]request packet received")
    # create ack packet
    ethr = Ether(dst=global_mac_broadcast)
    ip = IP(src=dhcp_server_ip, dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    boot_p = BOOTP(op=2, yiaddr=global_client_ip, siaddr=dhcp_server_ip, chaddr=global_client_mac)
    dhcp = DHCP(options=[("message-type", "ack"),
                         ("name_server", global_dns_server),  # dns server ip
                         'end'])
    ack_packet = ethr/ip/udp/boot_p/dhcp
    # send ack packet to client
    sendp(ack_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]ack packet sent")


def start_dhcp_server():
    # sniff the Discover packet
    print("[+]listening for discover packet")
    sniff(count=1, filter="udp and (port 67 or port 68)", prn=handle_discover_packet)
    # sniff request packet
    print("[+]listening for request packet")
    sniff(count=1, filter="udp and (port 67 or port 68)", prn=handle_request_packet)


if __name__ == '__main__':
    start_dhcp_server()

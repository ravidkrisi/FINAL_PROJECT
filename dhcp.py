from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import getmac
import time

# define dhcp server mac address and IP
dhcp_server_mac = getmac.get_mac_address()  # get local mac address
dhcp_server_ip = "192.168.1.1"

# define global variables
global_client_mac = getmac.get_mac_address()
global_client_ip = "192.168.1.100"


def create_offer_packet():
    ether = Ether(dst=global_client_mac)
    ip = IP(src=dhcp_server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    boot_p = BOOTP(op=2, yiaddr=global_client_ip, siaddr=dhcp_server_ip, chaddr=mac2str(global_client_mac), xid=1234)
    dhcp = DHCP(options=[("message-type", "offer"),
                         ("subnet_mask", "255.255.255.0"),
                         ("router", "192.168.1.1"),
                         "end"])
    return ether/ip/udp/boot_p/dhcp


def create_ack_packet():
    ethr = Ether(dst=global_client_mac)
    ip = IP(src='192.168.1.1', dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    boot_p = BOOTP(op=2, yiaddr=global_client_ip, siaddr='192.168.1.1', chaddr=global_client_mac)
    dhcp = DHCP(options=[('message-type', 'ack'),
                         ('server_id', '192.168.1.1'),
                         ('lease_time', 86400),
                         ('subnet_mask', '255.255.255.0'),
                         ('name_server', '192.168.1.2'),  # dns server ip
                         'end'])
    return ethr/ip/udp/boot_p/dhcp


if __name__ == '__main__':
    # sniff the discover packet
    print("[+]listening for discover packet")
    discover_packet = sniff(count=1, filter="udp and (port 67 or port 68)")
    print("[+]received discover packet")
    # create offer packet
    offer_packet = create_offer_packet()
    # send offer packet to client
    time.sleep(2)
    sendp(offer_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]offer packet sent")
    # sniff request packet
    print("[+]listening for request packet")
    request_packet = sniff(count=1, filter="udp and (port 67 or port 68)")
    print("[+]request packet received")
    # create ack packet
    ack_packet = create_ack_packet()
    # send ack packet to client
    time.sleep(2)
    sendp(ack_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]ack packet sent")

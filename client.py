from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import getmac
import time

# define global variables
global_client_mac = getmac.get_mac_address()
global_client_ip = ""
global_dns_server = ""


dhcp_options = [("subnet_mask", "255.255.255.0"),
                ("router", "192.168.1.1"),
                ("domain", "example.com")]


# Create DHCP Discover packet
def create_discover_packet():
    eth = Ether(src=global_client_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    boot_p = BOOTP(op=1, chaddr=global_client_mac)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return eth / ip / udp / boot_p / dhcp


def handle_offer(offer_packet):
    print("[+]offer packet received")
    # extract offered ip and server ip
    global global_client_ip
    global_client_ip = offer_packet[BOOTP].yiaddr
    server_ip = offer_packet[DHCP].options[1][1]
    # create request packet
    eth = Ether(src=global_client_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    boot_p = BOOTP(op=1, chaddr=RandMAC())
    dhcp = DHCP(options=[("message-type", "request"),
                        ("requested_addr", global_client_ip),
                        ("server_id", server_ip),
                        ("subnet_mask", "255.255.255.0"),
                        ("router", "192.168.1.1"),
                        ("domain", "example.com"),
                         "end"])
    request_packet = eth/ip/udp/boot_p/dhcp
    # send request packet
    sendp(request_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]request packet sent")

def handle_ack(packet):
    # Check if this is a DHCP ACK packet
    if packet[DHCP].options[0][1] == 5:
        # Extract the DNS server IP address from the DHCP options field
        for option in packet[DHCP].options:
            if option[0] == 'name_server':
                global global_dns_server
                global_dns_server = option[1]
                print(global_dns_server)


if __name__ == '__main__':
    # create discover packet
    discover_packet = create_discover_packet()
    # send discover packet
    sendp(discover_packet, iface="Intel(R) Wi-Fi 6 AX201 160MHz")
    print("[+]discover packet sent")
    # sniff offer packet
    print("[+]listening for offer packet")
    sniff(count=1, filter="udp and (port 67 or port 68)", prn=handle_offer)
    # sniff ack packet
    print("[+]listening for ack packet")
    ack_packet = sniff(count=1, filter="udp and (port 67 or port 68)", prn=handle_ack)
    print("[+]ack packet received")

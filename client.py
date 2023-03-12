from PIL import Image

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.l2 import *
import getmac
from scapy.layers.dns import *
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter


# define global variables
global_client_mac = getmac.get_mac_address()
global_client_ip = ""
global_dns_server = ""
global_url = ""
global_domain_name = ""
global_domain_ip = ""
global_domain_port = 0
global_mac_broadcast = "ff:ff:ff:ff:ff:ff"
global_file_name = ""
global_interface = ""


def get_interface():
    # get interface from user
    global global_interface
    global_interface = input("enter inteface to use:")


# Create DHCP Discover packet
def create_discover_packet():
    eth = Ether(dst=global_mac_broadcast)
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    boot_p = BOOTP(op=1, chaddr=global_client_mac)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return eth / ip / udp / boot_p / dhcp


def handle_offer(packet):
    print("[+]offer packet received")
    # extract offered ip and server ip
    offered_ip = packet[BOOTP].yiaddr
    # create request packet
    eth = Ether(dst=global_mac_broadcast)
    ip = IP(src="0.0.0.0", dst=packet[IP].src)
    udp = UDP(sport=68, dport=67)
    boot_p = BOOTP(op=1, chaddr=global_client_mac)
    dhcp = DHCP(options=[("message-type", "request"),
                        ("requested_addr", offered_ip),
                         "end"])
    request_packet = eth/ip/udp/boot_p/dhcp
    # send request packet
    sendp(request_packet, iface=global_interface)
    print("[+]request packet sent")


def handle_ack(packet):
    # check if its an ack packet
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        # store the offered client's IP
        global global_client_ip
        global_client_ip = packet[BOOTP].yiaddr
        print(f"client's IP: {global_client_ip}")
        # store the DNS server's IP
        for option in packet[DHCP].options:
            if option[0] == 'name_server':
                global global_dns_server
                global_dns_server = option[1]
                print(f"dns server IP: {global_dns_server}")
                # raise a random exception to mark we received the right packet
                raise KeyboardInterrupt


def create_dns_req_packet():
    # Define the DNS query
    query = DNS(rd=1, qd=DNSQR(qname=global_domain_name))
    # Define the IP and UDP headers
    ip = IP(dst=global_dns_server, src=global_client_ip)
    udp = UDP(sport=20331, dport=53)
    # Construct the packet
    packet = ip/udp/query
    return packet


def handle_dns_res_packet(packet):
    print("[+]received dns response packet")
    # extract web IP
    global global_domain_ip
    global_domain_ip = packet[DNSRR].rdata


def handle_dhcp_server():
    # get interface from user
    get_interface()
    # create discover packet
    discover_packet = create_discover_packet()
    # send discover packet
    sendp(discover_packet, iface=global_interface)
    print("[+]discover packet sent")
    # sniff offer packet
    print("[+]listening for offer packet")
    sniff(count=1, filter="udp and (port 67 or port 68)", prn=handle_offer)
    # sniff ack packet and filter out nack packet sent by the real dhcp server
    try:
        print("[+]listening for ack packet")
        ack_packet = sniff(filter="udp and (port 67 or port 68)", prn=handle_ack)
    # wait for exception when the client receive the ack packet that was expected
    except KeyboardInterrupt:
        print("[+]ack packet received")


def handle_dns_server():
    # create dns reqeust
    dns_req = create_dns_req_packet()
    # send dns request packet
    send(dns_req)
    # sniff dns response packet
    sniff(count=1, filter="udp and dst port 20331", prn=handle_dns_res_packet)


def get_url_input():
    # get url input from user
    global global_url
    global_url = input("enter url:")
    while not valid_url(global_url):
        global_url = input("enter valid url:")


def valid_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.netloc:
        return True
    return False


def extract_domain_name():
    # parse the url
    parsed_url = urlparse(global_url)
    # extract the domain name from the parsed url
    global global_domain_name
    global_domain_name = parsed_url.hostname


def url_with_ip():
    # swipe the domain name with its corresponding ip
    return global_url.replace(global_domain_name, global_domain_ip)


def extract_file_name():
    global global_file_name
    file_name = os.path.basename(global_url)
    global_file_name = file_name.split(".")[0]+"_client."+file_name.split(".")[1]


def handle_web_server_app():
    # get url input from user
    get_url_input()
    # extract domain name from url
    extract_domain_name()
    # get domain ip by requesting it from DNS server
    handle_dns_server()
    # create new url using corresponding ip of domain name
    new_url = url_with_ip()
    # extract file name of url
    extract_file_name()
    # send GET request to domain and get the response
    response = requests.get(new_url)
    print("[+]url requested")
    # check if we received the correct infomarmtion we request
    if response.status_code == 200:
        # open a jpg file to store to photo

        with open(global_file_name, 'wb') as file:
            file.write(response.content)
            print("image saved to files(:")

        # Open the image
        image = Image.open(global_file_name)
        # Show the image on screen
        image.show()

    else:
        print("Sorry it didn't work you are a bad programmer")


if __name__ == '__main__':
    # ask for an internet configuration from the dhcp server
    handle_dhcp_server()
    # start the web application handler
    handle_web_server_app()








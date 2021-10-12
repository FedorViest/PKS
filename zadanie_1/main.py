import scapy.all as scapy
from scapy.all import rdpcap


def print_frame_info(frame):
    print("Source mac adress:", get_source_mac(frame))
    print("Destination mac adress:", get_dest_mac(frame))
    frame_length = len(frame) / 2
    if frame_length < 60:
        frame_length = 64
    print("Frame length by pcap API: " + str(frame_length) + "\nFrame length distributed by medium: " + str(
        (frame_length + 4)))
    ip_adresses = get_frame_type(frame)
    print()
    print_frame(frame)
    print("\n\n")
    return ip_adresses


def get_source_mac(smac_frame):
    return format_mac(smac_frame[12:24])


def get_dest_mac(dmac_frames):
    return format_mac(dmac_frames[0:12])


def format_mac(mac_addr_to_format):
    mac_addr_to_format = ':'.join(mac_addr_to_format[i:i + 2] for i in range(0, len(mac_addr_to_format), 2))
    return mac_addr_to_format


def get_dest_ip(frame):
    ip = frame[60:68]
    return ip


def get_source_ip(frame):
    ip = frame[52:60]
    return ip


def format_ip(ip):
    ip_to_dec = [ip[i:i + 2] for i in range(0, len(ip), 2)]
    ip_new = [int(i, 16) for i in ip_to_dec]
    ip_format = '.'.join(str(i) for i in ip_new)
    return ip_format


def print_frame(frame):
    count = 0
    for i in frame:
        print(i, end='')
        count += 1
        if count % 2 == 0:
            print(" ", end='')
        if count % 32 == 0:
            print()
            continue
        if count % 16 == 0:
            print('  ', end='')
    print()
    print()


def get_ethernet_protocol():
    e_type = {}
    with open("EthertypeValues.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            e_type[type[0]] = type[1][0:-1]
    return e_type


def get_802_protocol():
    type802 = {}
    with open("LLC_SAPs.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            type802[type[0]] = type[1][0:-1]
    return type802


def get_ip_protocol():
    protocol = {}
    with open("Protocols.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            protocol[type[0]] = type[1][0:-1]
    return protocol


"""
Funkcia na zistenie typu ramca
"""


def get_frame_type(frame):
    size = int(frame[24:28], 16)
    ip_addresses = []
    if size > 1536:
        print("Ethernet II")
        ip_addresses = get_ether_protocol(frame, "Ethernet II")
    else:
        size = frame[28:30]
        if size == "aa":
            print("IEEE 802.3 LLC + SNAP")
            get_ether_protocol(frame, "SNAP")
        # ak je raw, tak je IPX header
        elif size == "ff":
            print("\tIEEE 802.3 RAW" + "\n\t\tProtocol: IPX")
        else:
            protocol = get_LLC_protocol(frame)
            print("\tIEEE 802.3 LLC" + "\n\t\tProtocol: " + protocol)
    return ip_addresses


def get_LLC_protocol(frame):
    protocol = get_802_protocol()
    keys = protocol.keys()
    for key in keys:
        if key == frame[28:30]:
            return protocol[key]


def get_ether_protocol(frame, type):
    ip_addresses = []
    if type == "Ethernet II":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        for key in keys:
            if key == frame[24:28]:
                if dict[key] == "Internet IP (IPv4)":
                    dest_ip = str(get_dest_ip(frame))
                    source_ip = str(get_source_ip(frame))
                    dest_ip = format_ip(dest_ip)
                    source_ip = format_ip(source_ip)
                    protocol = get_IPv4_protocol(frame)
                    ip_addresses.append(source_ip)
                    print("\t" + dict[key] + "\n\t\tSource ip address: " + str(
                        source_ip) + "\n\t\tDestination ip address: " + str(dest_ip) + "\n\t\tProtocol: " + protocol)
                    break
                elif dict[key] == "ARP (Address Resolution Protocol)":
                    print("\t" + dict[key])
                    break
    elif type == "SNAP":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        for key in keys:
            if key == frame[40:44]:
                print("\tProtocol: " + dict[key])
                break
    return ip_addresses


def get_IPv4_protocol(frame):
    protocol = frame[46:48]
    loaded_protocol = get_ip_protocol()
    keys = loaded_protocol.keys()
    for key in keys:
        if protocol == key:
            return loaded_protocol[key]
    return "Couldn't resolve protocol"


def count_ip(ips):
    ip_list = {}
    ips.reverse()
    unique_list = []
    counts = []
    for ip in ips:
        count = ips.count(ip)
        if ip not in unique_list:
            counts.append(count)
            unique_list.append(ip)
    temp = list(unique_list)
    for count in counts:
        for unique in temp:
            ip_list[count] = unique
            temp.remove(unique)
            break
    sort_ips = sorted(ip_list.items(), reverse=True)
    print("IP adresses of all sending nodes: ")
    for i in unique_list:
        print(i)
    print("Found: {} unique IP addresses".format(len(unique_list)))
    print()
    ip = list(sort_ips[0])
    print("IP address which sent the most packets: " + str(ip[1]) + ", with: " + str(ip[0]) + " packets sent")


def print_all(frames):
    ip_adresses = []
    flag = 0
    for index in range(len(frames)):
        print("Frame number: %d" % (index + 1))
        ip_adress = print_frame_info(frames[index])
        if ip_adress:
            flag = 1
            ip_adresses.append(ip_adress[0])
    if ip_adresses:
        ip_adresses.sort()
        count_ip(ip_adresses)
    else:
        print("No IPv4 protocols were found\n\n")


pcap = rdpcap("./vzorky_pcap_na_analyzu/trace-26.pcap")
#pcap = rdpcap("trace-26.pcap")
frames = []
index = 0
for pkt in pcap:
    raw = scapy.raw(pkt)
    frames.append("".join(["{:02x}".format(x) for x in raw]))

handler = str(input("Pick your option: "))
while handler != "exit":
    if handler == "all":
        print_all(frames)
    elif handler == "exit":
        exit(0)
    else:
        print("Invalid input, please select again")
    handler = str(input("\nPick your option: "))

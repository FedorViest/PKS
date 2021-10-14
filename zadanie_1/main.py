import scapy.all as scapy
from scapy.all import rdpcap
import sys


"""
Funkcia na sumarny vypis ramcov
"""

def print_all(frames, handler, icmp, arp, http, https, telnet, ssh, ftp, flag):
    ip_adresses = []
    for index in range(len(frames)):
        print("Frame number: %d" % (index + 1))
        ip_adress = print_frame_info(frames[index], handler, icmp, arp, http, https, telnet, ssh, ftp, index, flag)
        if ip_adress:
            ip_adresses.append(ip_adress[0])
    if ip_adresses:
        ip_adresses.sort()
        count_ip(ip_adresses)
    else:
        print("No IPv4 protocols were found\n\n")


"""
Funkcia na vypis ICMP typov pre bod 4
"""


def print_icmp(frames, icmp):
    i = 0
    if len(icmp) == 0:
        print("No ICMP protocols were found\n\n")
        return
    if len(icmp) > 20:
        for index in range(len(frames)):
            if icmp[i] == index:
                if i < 10 or i >= len(icmp) - 10:
                    print("Frame number: %d" % (index + 1))
                    print_frame_info(frames[index], handler, icmp, arp, http, https, telnet, ssh, ftp, index, False)
                i += 1
                if i > len(icmp) - 1:
                    break
    else:
        for index in range(len(frames)):
            if icmp[i] == index:
                print("Frame number: %d" % (index + 1))
                print_frame_info(frames[index], handler, icmp, arp, http, https, telnet, ssh, ftp, index, False)
                i += 1
                if i > len(icmp) - 1:
                    break


"""
Funkcia na vypis informacii o ramci
"""


def print_frame_info(frame, handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag):
    # Vypise zdrojovu naformatovanu mac adresu
    print("Source mac adress:", get_source_mac(frame))
    # Vypise koncovu naformatovanu mac adresu
    print("Destination mac adress:", get_dest_mac(frame))
    frame_length = len(frame) / 2
    if frame_length < 60:
        frame_length = 60
    # Vypis dlzky ramca
    print("Frame length by pcap API: " + str(len(frame) / 2) + "\nFrame length distributed by medium: " + str(
        (frame_length + 4)))
    # Zavolanie funkcie na zistanie dalsic informacii o ramci
    ip_adresses = get_frame_type(frame, handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag)
    print()
    # Vypis dat v ramci
    print_frame(frame)
    print("\n")
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


"""
Funkcia na naformatovanie ip adresy
"""


def format_ip(ip):
    ip_to_dec = [ip[i:i + 2] for i in range(0, len(ip), 2)]
    ip_new = [int(i, 16) for i in ip_to_dec]
    ip_format = '.'.join(str(i) for i in ip_new)
    return ip_format


"""
Funkcia na vypisanie ramca v hexadecimalnom formate
"""


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


"""
Funkcia, ktora nacita Ethernet protokoly do slovnika
"""


def get_ethernet_protocol():
    e_type = {}
    with open("EthertypeValues.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            e_type[type[0]] = type[1][0:-1]
    return e_type


"""
Funkcia, ktora nacita IEEE 802.3 protokoly do slovnika
"""


def get_802_protocol():
    type802 = {}
    with open("LLC_SAPs.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            type802[type[0]] = type[1][0:-1]
    return type802


"""
Funkcia, ktora nacita IPv4 protokoly do slovnika
"""


def get_ip_protocol():
    protocol = {}
    with open("Protocols.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            protocol[type[0]] = type[1][0:-1]
    return protocol


"""
Funkcia, ktora nacita IPv4 typy zo slovnika a vrati typ IPv4, ak najde zhodu
"""


def get_IPv4_protocol(frame):
    protocol = frame[46:48]
    loaded_protocol = get_ip_protocol()
    keys = loaded_protocol.keys()
    for key in keys:
        if protocol == key:
            return loaded_protocol[key]
    return "Couldn't resolve protocol"


"""
Funkcia, ktora nacita ICMP typy do slovnika
"""


def get_icmp_types():
    icmps = {}
    with open("ICMP.txt") as file:
        lines = file.readlines()
        for line in lines:
            type = line.split("=")
            icmps[type[0]] = type[1][0:-1]
    return icmps


"""
Funkcia na zistenie typu ramca
"""


def get_frame_type(frame, handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag):
    size = int(frame[24:28], 16)
    ip_addresses = []
    if size > 1536:
        print("Ethernet II")
        ip_addresses = get_ether_protocol(frame, "Ethernet II", handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag)
    else:
        size = frame[28:30]
        if size == "aa":
            print("IEEE 802.3 LLC + SNAP")
            get_ether_protocol(frame, "SNAP", handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag)
        # ak je raw, tak je IPX header
        elif size == "ff":
            print("\tIEEE 802.3 RAW" + "\n\t\tProtocol: IPX")
        else:
            protocol = get_LLC_protocol(frame)
            print("\tIEEE 802.3 LLC" + "\n\t\tProtocol: " + protocol)
    return ip_addresses


"""
Funkcia, ktora nacita LLC protokoly do slovnika
"""


def get_LLC_protocol(frame):
    protocol = get_802_protocol()
    keys = protocol.keys()
    for key in keys:
        if key == frame[28:30]:
            return protocol[key]
    return "Unknown protocol"


"""
Funkcia na zistenie typu ramca, v ktorej sa taktiez zistuje vnoreny protokol a informacie o vnorenom protokole
"""


def get_ether_protocol(frame, type, handler, icmp, arp, http, https, telnet, ssh, ftp, number, flag):
    ip_addresses = []
    if type == "Ethernet II":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        for key in keys:
            if key == frame[24:28]:
                print("\t" + dict[key])
                if dict[key] == "Internet IP (IPv4)":
                    dest_ip = str(get_dest_ip(frame))
                    source_ip = str(get_source_ip(frame))
                    dest_ip = format_ip(dest_ip)
                    source_ip = format_ip(source_ip)
                    protocol = get_IPv4_protocol(frame)
                    ip_addresses.append(source_ip)
                    print("\t\tSource ip address: " + str(
                        source_ip) + "\n\t\tDestination ip address: " + str(dest_ip) + "\n\t\tProtocol: " + protocol)
                    if handler == "icmp" and protocol == "ICMP":
                        icmps = get_icmp_types()
                        icmp_keys = icmps.keys()
                        index = get_header_size(frame) + 28
                        if flag:
                            icmp.append(number)
                        no_icmp = 1
                        for icmp_key in icmp_keys:
                            if icmp_key == frame[index:index + 2]:
                                no_icmp = 0
                                print("\t\t" + icmps[icmp_key])
                                break
                        if no_icmp:
                            print("\tUnknown ICMP type")
                    #elif handler == "udp" and protocol == "UDP":

                    break
                elif dict[key] == "ARP (Address Resolution Protocol)":
                    break
    elif type == "SNAP":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        for key in keys:
            if key == frame[40:44]:
                print("\tProtocol: " + dict[key])
                break
    return ip_addresses


"""
Funkcia na zistenie velkosti hlavicky
"""


def get_header_size(frame):
    size = int(frame[29]) * 4 * 2
    return size


"""
Funckia na detailny vypis ip adries
"""


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


"""
Pomocne funkcie na zacatie vypisu do suboru a nasledne zrusenie vypisu do suboru
"""


def open_file(file, write):
    if write == "y":
        sys.stdout = file


def reverse_file(write):
    if write == "y":
        sys.stdout = sys.__stdout__


def menu():
    print("y - to write output into file")
    print("n - to write output into CLI")
    print("all - to print every frame info")
    print("icmp - to print all icmp communications")
    print("exit - to terminate program")


def load(frames, handler, icmp, arp, http, https, telnet, ssh, ftp):
    file = open("Output.txt", "w")
    open_file(file, "y")
    print_all(frames, handler, icmp, arp, http, https, telnet, ssh, ftp, True)
    reverse_file("y")
    file.close()


start_file = input("Select pcap file to analyze:")
pcap = rdpcap("./vzorky_pcap_na_analyzu/" + start_file + ".pcap")
frames = []
index = 0
for pkt in pcap:
    raw = scapy.raw(pkt)
    frames.append("".join(["{:02x}".format(x) for x in raw]))

menu()
icmp = []
arp = []
http = []
https = []
telnet = []
ssh = []
ftp = []
write = input("[y/n] print to file: ")
handler = str(input("Pick your option: "))
while handler != "exit":
    if write == "y":
        file = open("Output.txt", "w")
    else:
        file = None
    if handler == "all":
        file = open("Output.txt", "w")
        open_file(file, write)
        print_all(frames, handler, icmp, arp, http, https, telnet, ssh, ftp, True)
        reverse_file(write)
        file.close()
    elif handler == "icmp":
        icmp = []
        load(frames, handler, icmp, arp, http, https, telnet, ssh, ftp)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("ICMP Communication\n\n")
        print_icmp(frames, icmp)
        reverse_file(write)
        file2.close()
    elif handler == "tftp":
        continue
    elif handler == "exit":
        if write == "y":
            file.close()
        exit(0)
    else:
        print("Invalid input, please select again")
    menu()
    write = str(input("[y/n] print to file: "))
    handler = str(input("\nPick your option: "))
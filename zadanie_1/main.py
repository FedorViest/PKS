import scapy.all as scapy
from scapy.all import rdpcap
import sys


"""
Funkcia na sumarny vypis ramcov
"""


def print_all(frames, handler, icmp, tftp, arp, tcps, flag):
    ip_adresses = []
    for index in range(len(frames)):
        print("Frame number: %d" % (index + 1))
        ip_adress = print_frame_info(frames[index], handler, icmp, tftp, arp, tcps, index, flag)
        if ip_adress:
            ip_adresses.append(ip_adress[0])
    if ip_adresses:
        ip_adresses.sort()
        count_ip(ip_adresses)
    else:
        print("No IPv4 protocols were found\n\n")


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
Funkcia na vypis informacii o ramci
"""


def print_frame_info(frame, handler, icmp, tftp, arp, tcps, number, flag):
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
    ip_adresses = get_frame_type(frame, handler, icmp, tftp, arp, tcps, number, flag)
    print()
    # Vypis dat v ramci
    print_frame(frame)
    print("\n")
    return ip_adresses


"""
Funkcia na vypis ICMP typov pre bod 4
"""


def print_icmp(frames, icmp):
    i = 0
    if len(icmp) == 0:
        print("No ICMP protocols were found\n\n")
        return
    for index in range(len(frames)):
        if icmp[i] == index:
            if i < 10 or i >= len(icmp) - 10:
                print("Frame number: %d" % (index + 1))
                print_frame_info(frames[index], handler, icmp, tftp, arp, tcps, index, False)
            i += 1
            if i > len(icmp) - 1:
                break


"""
Funkcia na vypis TFTP komunikacie
"""


def print_tftp(frames, tftp):
    comms = []
    ports = []
    temp = []
    final = []
    # Tu si pridavam do listu zaciatky komunikacii
    for index in range(len(tftp)):
        if tftp[index][1] == 69 or tftp[index][2] == 69:
            comms.append(tftp[index])
    # V ramcoch pozeram na dalsi port po 69 a pridavam ho do listu portov, podla coho viem urcit, ze ide o jednu komunikaciu
    for comm in range(len(comms)):
        if comms[comm][1] == 69:
            ports.append(comms[comm][2])
        elif comms[comm][2] == 69:
            ports.append(comms[comm][1])
    for port in range(len(ports)):
        for index in range(len(tftp)):
            if (tftp[index][1] == ports[port] or tftp[index][2] == ports[port]) and (comms[port][0] <= tftp[index][0]):
                temp.append(tftp[index][0])
        final.append(temp)
        temp = []
    if len(ports) == 0:
        print("No TFTP communications found")
    index = 1
    counter = 0
    for communication in final:
        print("\t\t\t\tCommunication number: " + str(index) + "\n\n")
        index += 1
        for frame in communication:
            if counter < 10 and counter >= len(communication) - 10:
                print("Frame number: %d" % (frame + 1))
                print_frame_info(frames[frame], handler, icmp, tftp, arp, tcps, index, False)
            counter += 1


"""
Funkcia na zoskupenie ARP komunikacii a nasledne vypisanie
Do funkice posielam vsetky nacitane ramce a vsetky ARP v poli
"""


def print_arp(frames, arps):
    comms = []
    if len(arps) == 0:
        print("No ARP communications found")
    # V cykle prechadzam ARP komunikacie a kontrolujem ci uz mam zapisanu komunikaciu s rovnakymi parametrami,
    # ak nie, pridavam ju ako novy index v liste. Nakoniec kazdej ukoncenej komunikacie pridavam 'end', aby som vedel
    # ci uz je komunikacia ukoncena
    for arp in arps:
        paired_arps = []
        if arp[1] == "request":
            if arp_request(arp, comms):
                continue
            else:
                paired_arps.append(arp)
                comms.append(paired_arps)
        else:
            if arp_reply(arp, comms):
                continue
            else:
                paired_arps.append(arp)
                paired_arps.append("end")
                comms.append(paired_arps)
    complete = []
    incomplete = []
    for com in comms:
        if com[-1][-1] == "end":
            complete.append(com)
        else:
            incomplete.append(com)
    index = 1
    if complete:
        for com in complete:
            print("\t\t\t\nComplete Communication number:", index)
            print()
            index += 1
            if com[-1][-1] == "end" and len(com) >= 2:
                for counter in range(len(com)):
                    if 10 > counter >= len(com) - 10:
                        print("ARP-" + com[counter][1] + "\nSource ip address: " + com[counter][2] + "\tDestination ip address: "\
                        + com[counter][3] + "\nSource mac: " + com[counter][4] + "\tDestination mac: " + com[counter][5])
                        print("Frame number: ", str(com[counter][0] + 1))
                        print_frame_info(frames[com[counter][0]], handler, icmp, tftp, arp, tcps, index, False)
    if incomplete:
        index = 1
        for com in incomplete:
            print("\t\t\t\nIncomplete Communication number:", index)
            print()
            index += 1
            if com[-1][-1] != "end" and com[-1] != "end":
                for counter in range(len(com)):
                    if 10 > counter >= len(com) - 10:
                        print("ARP-" + com[counter][1] + "\nSource ip address: " + com[counter][2] + "\tDestination ip address: "\
                        + com[counter][3] + "\nSource mac: " + com[counter][4] + "\tDestination mac: " + com[counter][5])
                        print("Frame number: ", str(com[counter][0] + 1))
                        print_frame_info(frames[com[counter][0]], handler, icmp, tftp, arp, tcps, index, False)
            elif com[-1] == "end":
                print("ARP-" + com[0][1] + "\nSource ip address: " + com[0][2] + "\tDestination ip address: "\
                + com[0][3] + "\nSource mac: " + com[0][4] + "\tDestination mac: " + com[0][5])
                print("Frame number: ", str(com[0][0] + 1))
                print_frame_info(frames[com[0][0]], handler, icmp, tftp, arp, tcps, index, False)


def arp_request(arp, comms):
    counter = 0
    if comms:
        for index in comms:
            temp = []
            #Kontrola ip adries, mac adries a ci komunikacia nie je ukoncena
            if arp[2] == index[0][2] and arp[3] == index[0][3] and arp[4] == index[0][4] and arp[5] == index[0][5] and index[-1][-1] != "end":
                temp.append(arp)
                comms[counter].append(arp)
                return 1
            counter += 1
    return 0


def arp_reply(arp, comms):
    counter = 0
    if comms:
        for index in comms:
            temp = []
            if arp[2] == index[0][3] and arp[3] == index[0][2] and arp[5] == index[0][4] and index[-1][-1] != "end":
                temp.append(arp)
                arp.append("end")
                comms[counter].append(arp)
                return 1
            counter += 1
    return 0


def analyze_arp(frame, number):
    arp_info = []
    type = int(frame[40:44], 16)
    if type == 1:
        type = "request"
    elif type == 2:
        type = "reply"
    source_ip = format_ip(frame[56:64])
    source_mac = format_mac(frame[44:56])
    dest_ip = format_ip(frame[76:84])
    dest_mac = format_mac(frame[64:76])
    arp_info.extend((number, type, source_ip, dest_ip, source_mac, dest_mac))
    print(arp_info)
    return arp_info


"""
Funkcia na zistenie informacii o TCP komunikaciach
"""


def handle_tcp(frame, tcps, number, src_ip, dest_ip, print_ports):
    #Zistim si porty, typy TCP a flag, ktore potom posielam ako parametre do funkcie
    header = get_header_size(frame) + 28
    source_port = int(frame[header:header + 4], 16)
    dest_port = int(frame[header + 4:header + 8], 16)
    tcp_types = load_TCP_type()
    keys = tcp_types.keys()
    type = ""
    tcp_info = []
    for key in keys:
        if key == str(source_port) or key == str(dest_port):
            type = tcp_types[key]
            break
    flag = frame[header + 26: header + 28]
    flag = str(bin(int(flag, 16))[2:].zfill(5))
    flag = flag[::-1]

    if type:
        tcp_info.extend((number, flag, source_port, dest_port, src_ip, dest_ip, type))
        tcps.append(tcp_info)
    if print_ports:
        if type:
            print("\t\t\t" + str(type).upper())
        else:
            print("\t\t\tUnknown source and destination ports")
        print("\t\t\tSource port: " + str(source_port) + "\n\t\t\tDestination port:" + str(dest_port))


"""
Funkcia na kontrolovanie, ci su komunikacie kompletne alebo nekompletne a nasledny vypis tychto komunikacii
"""


def tcp_communication(frames, tcps, type):
    comms = []
    for tcp in tcps:
        temp = []
        if group_comms(tcp, comms):
            continue
        else:
            temp.append(tcp)
            comms.append(temp)
    printing_complete = True
    printing_incomplete = True
    for com in comms:
        corr_start = False
        corr_end = False

        if len(com) > 4 and type == com[0][6]:
            first = com[0][1]
            second = com[1][1]
            third = com[2][1]
            #Kontrola, ci je komunikacia spravne otvorena
            if first[1] == "1" and second[1] == "1" and second[4] == "1" and third[4] == "1":
                corr_start = True
            if corr_start:
                fin = False
                fin_ack = False
                ack = False
                # Kontrola, ci je komunikacia spravne uzatvorena
                for com_n in range(len(com)):
                    if com[com_n][1][0] == "1" and not fin:
                        fin = True
                        continue
                    elif com[com_n][1][0] == "1" and com[com_n][1][4] == "1" and fin and not fin_ack:
                        fin_ack = True
                        continue
                    elif com[com_n][1][4] == "1" and fin and fin_ack:
                        ack = True
                        continue
                    elif com[com_n][1][2] == "1":
                        corr_end = True
                        break
                    elif fin and fin_ack and ack:
                        corr_end = True
                        break
                if fin and fin_ack and ack:
                    corr_end = True

        if printing_complete:
            if corr_start and corr_end:
                print("\t\t\t\t\tComplete " + type.upper() + " communication:\n")
                counter = 0
                for i in com:
                    if counter < 10 or counter >= len(com) - 10:
                        print("Source port: " + str(i[2]) + "\tDestination port: " + str(i[3]))
                        print("Frame number: ", str(int(i[0]) + 1))
                        print_frame_info(frames[i[0]], handler, icmp, tftp, arp, tcps, index, False)
                    counter += 1
                printing_complete = False

        if printing_incomplete:
            if corr_start and not corr_end:
                print("\t\t\t\t\tInomplete " + type.upper() + " communication:\n")
                counter = 0
                for i in com:
                    if counter < 10 or counter >= len(com) - 10:
                        print("Source port: " + str(i[2]) + "\tDestination port: " + str(i[3]))
                        print("Frame number: ", str(int(i[0]) + 1))
                        print_frame_info(frames[i[0]], handler, icmp, tftp, arp, tcps, index, False)
                    counter += 1
                printing_incomplete = False
    if printing_complete:
        print("\t\t\t\t\tNo complete " + type.upper() + " communication\n\n")
    if printing_incomplete:
        print("\t\t\t\t\tNo incomplete " + type.upper() + " communication\n\n")


"""
Funkcia na zoskupenie TCP ramcov, ktore maju rovnake ip a mac adresy a ci sa rovnaju typy TCP ramcov
"""


def group_comms(tcp, comms):
    counter = 0
    if comms:
        for com in comms:
            temp = []
            if tcp[6] == com[0][6] and (tcp[2] == com[0][2] and tcp[3] == com[0][3] and tcp[4] == com[0][4] and tcp[5] == com[0][5]) \
                or (tcp[2] == com[0][3] and tcp[3] == com[0][2] and tcp[4] == com[0][5] and tcp[5] == com[0][4]):
                temp.append(tcp)
                comms[counter].append(tcp)
                return 1
            counter += 1
    return 0


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
Funkcia na zistenie velkosti hlavicky
"""


def get_header_size(frame):
    size = int(frame[29], 16) * 4 * 2
    return size


def tftp_source_port(frame, header):
    return int(frame[header:header + 4], 16)


def tftp_dest_port(frame, header):
    return int(frame[header + 4:header + 8], 16)


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
Funkcia, ktora nacita LLC protokoly do slovnika
"""


def get_LLC_protocol(frame):
    protocol = get_802_protocol()
    keys = protocol.keys()
    for key in keys:
        if key == frame[28:30]:
            return protocol[key]
    return "Unknown protocol"


def load_udp_type():
    type = {}
    with open("UDP.txt") as file:
        lines = file.readlines()
        for line in lines:
            temp = line.split("=")
            type[temp[0]] = temp[1][0:-1]
    return type


def load_TCP_type():
    type = {}
    with open("TCP.txt") as file:
        lines = file.readlines()
        for line in lines:
            temp = line.split("=")
            type[temp[0]] = temp[1][0:-1]
    return type


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


def get_frame_type(frame, handler, icmp, tftp, arp, tcps, number, flag):
    size = int(frame[24:28], 16)
    ip_addresses = []
    if size > 1536:
        print("Ethernet II")
        ip_addresses = get_ether_protocol(frame, "Ethernet II", handler, icmp, tftp, arp, tcps, number, flag)
    else:
        size = frame[28:30]
        if size == "aa":
            print("IEEE 802.3 LLC + SNAP")
            get_ether_protocol(frame, "SNAP", handler, icmp, tftp, arp, tcps, number, flag)
        # ak je raw, tak je IPX header
        elif size == "ff":
            print("\tIEEE 802.3 RAW" + "\n\t\tProtocol: IPX")
        else:
            protocol = get_LLC_protocol(frame)
            print("\tIEEE 802.3 LLC" + "\n\t\tProtocol: " + protocol)
    return ip_addresses


"""
Funkcia na zistenie typu ramca, v ktorej sa taktiez zistuje vnoreny protokol a informacie o vnorenom protokole
"""


def get_ether_protocol(frame, type, handler, icmp, tftp, arp, tcps, number, flag):
    ip_addresses = []
    if type == "Ethernet II":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        # Zistovanie vnutorneho protokolu
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
                    index = get_header_size(frame) + 28
                    if handler == "icmp" and protocol == "ICMP":
                        icmps = get_icmp_types()
                        icmp_keys = icmps.keys()
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
                    elif protocol == "UDP":
                        src_port = tftp_source_port(frame, index)
                        dst_port = tftp_dest_port(frame, index)
                        udp_type = load_udp_type()
                        udp_keys = udp_type.keys()
                        udp = ""
                        for udp_key in udp_keys:
                            if udp_key == str(src_port) or udp_key == str(dst_port):
                                udp = udp_type[udp_key]
                                print("\t\t" + udp.upper())
                        if not udp:
                            print("\t\tUnknown protocol")
                        print("\t\tSource port:", src_port)
                        print("\t\tDestination port:", dst_port)
                        if handler == "tftp":
                            comm = []
                            comm.extend((number, src_port, dst_port))
                            if flag:
                                tftp.append(comm)
                    elif protocol == "TCP":
                        if handler == "all":
                            handle_tcp(frame, tcps, number, source_ip, dest_ip, True)
                        else:
                            handle_tcp(frame, tcps, number, source_ip, dest_ip, False)
                elif handler == "arp" and dict[key] == "ARP (Address Resolution Protocol)":
                    if flag:
                        arp.append(analyze_arp(frame, number))
    elif type == "SNAP":
        dict = get_ethernet_protocol()
        keys = dict.keys()
        for key in keys:
            if key == frame[40:44]:
                print("\tProtocol: " + dict[key])
                break
    return ip_addresses


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
    print("\n\n\ty - to write output into file")
    print("\tn - to write output onto CLI")
    print("\tall - to print every frame info")
    print("\ticmp - to print all icmp communications")
    print("\ttftp - to print all tftp communications")
    print("\tarp - to print all arp communications")
    print("\thttp - to print http communications")
    print("\thttps - to print https communications")
    print("\tssh - to print ssh communications")
    print("\ttelnet - to print telnet communications")
    print("\tftp-data - to print ftp-data communications")
    print("\tftp-control - to print ftp-control communications")
    print("\texit - to terminate program\n\n")


def load(frames, handler, icmp, tftp, arp, tcps):
    file = open("Output.txt", "w")
    open_file(file, "y")
    print_all(frames, handler, icmp, tftp, arp, tcps, True)
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
tcps = []
tftp = []
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
        print_all(frames, handler, icmp, tftp, arp, tcps, True)
        reverse_file(write)
        file.close()
    elif handler == "icmp":
        icmp = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("ICMP Communication\n\n")
        print_icmp(frames, icmp)
        reverse_file(write)
        file2.close()
    elif handler == "tftp":
        tftp = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("TFTP Communication\n\n")
        print_tftp(frames, tftp)
        reverse_file(write)
        file2.close()
    elif handler == "arp":
        arp = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("ARP Communication\n\n")
        print_arp(frames, arp)
        reverse_file(write)
        file2.close()
    elif handler == "http":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("HTTP Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "https":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("HTTPS Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "ssh":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("SSH Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "telnet":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("TELNET Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "ftp-control":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("FTP-CONTROL Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "ftp-data":
        tcps = []
        load(frames, handler, icmp, tftp, arp, tcps)
        file2 = open("Output.txt", "w")
        open_file(file2, write)
        print("FTP-DATA Communication\n\n")
        tcp_communication(frames, tcps, handler)
        reverse_file(write)
        file2.close()
    elif handler == "exit":
        if write == "y":
            file.close()
        exit(0)
    else:
        print("Invalid input, please select again")
    menu()
    write = str(input("\n[y/n] print to file: "))
    handler = str(input("Pick your option: "))
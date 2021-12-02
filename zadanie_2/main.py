import random
import math
import socket
import os
import sys
import threading
import time
import zlib
import struct  # https://docs.python.org/3/library/struct.html

CLIENT = 1  # client option
SERVER = 2  # server option

INIT = 0    # initialize communication
MSG = 1     # send message
FILE = 2    # send file
ACK = 3     # acknowledgement
NACK = 4    # negative acknowledgement
KPA = 5     # keep alive
SWAP = 6    # change roles
END = 7     # end communication


"""
Funkcia na vytvorenie hlavicky
"""


def create_header(packet_type, packet_number=0, crc=0, data=''.encode()):
    header = struct.pack("B", packet_type) + packet_number.to_bytes(3, byteorder="big") + \
             crc.to_bytes(4, byteorder="big") + struct.pack(f"{len(data)}s", data)
    return header


"""
Funkcia na desifrovanie dat z hlavicky, funkcia vracia typ spravy, cislo packetu, crc a data
"""


def get_header_data(data):
    packet_type, packet_number, crc, data = struct.unpack(f"B{3}s{4}s{len(data) - 8}s", data)
    packet_number = int.from_bytes(packet_number, byteorder="big")
    crc = int.from_bytes(crc, byteorder="big")
    return packet_type, packet_number, crc, data


def choose_roles():
    role = int(input("Select role:"
                     "\n\t[1] -> Client"
                     "\n\t[2] -> Server"
                     "\nRole: "))
    while role != 1 and role != 2:
        print("Invalid choice.")
        role = int(input("Select role:"
                         "\n\t[1] -> Client"
                         "\n\t[2] -> Server"
                         "\nRole: "))
    if role == CLIENT:
        client_connect()
    if role == SERVER:
        server_connect()

    return None


def client_menu():
    handler = int(input("\nSelect option:"
                        "\n\t[1] -> Send message"
                        "\n\t[2] -> Send file"
                        "\n\t[3] -> Swap roles"
                        "\n\t[4] -> End connection"
                        "\nOption: "))
    return handler


def client_connect():
    print("**********************   CLIENT   **********************")
    while True:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client_socket.settimeout(60)
            ip = input("Input ip address you want to connect to: ")
            port = int(input("Select port you want to connect to: "))
            server_addr = (ip, port)
            header = create_header(0, 0)        # Vytvorenie hlavicky na zacatie komunikacie
            client_socket.sendto(header, server_addr)   # Poslanie spravy na inicializaciu komunikacie
            data, addr = client_socket.recvfrom(1500)
            packet_type, packet_number, crc, recv_data = get_header_data(data)
            if packet_type == 3:    # Ak prisiel zo servra ACK
                print(f"\n\tSuccessfully connected to address {addr}")
                client(client_socket, server_addr)
            else:
                continue
        except socket.timeout:
            print("Connection Timeout")
            exit(0)


def client(client_socket, address):
    KPA_event = threading.Event()
    end_event = threading.Event()
    # Vytvorenie threadu na keep alive spolu s events, ktore mi hovoria, kedy sa ma keep alive vypnut
    thread = threading.Thread(target=keep_alive, args=(client_socket, address, KPA_event, end_event))
    thread.start()
    while True:
        try:
            frag_size = 1464

            client_socket.settimeout(20)

            KPA_event.set()

            handler = client_menu()
            error = 2

            # Ak si pouzivatel vybral MESSAGE alebo FILE, vypyta si od neho dalsie specifikacie
            if handler == 1 or handler == 2:
                frag_size = int(input("\nSelect maximum fragment size: "))
                while frag_size < 1 or frag_size > 1464:
                    print("Incorrect input (please select from range 1 - 1464)")
                    frag_size = int(input("\nSelect maximum fragment size: "))

                error = int(input("\nSend data with errors?\n\t[1] -> yes\n\t[2] -> no\nOption: "))
                while error != 1 and error != 2:
                    print("Incorrect input")
                    error = int(input("\nSend data with errors?\n\t[1] -> yes\n\t[2] -> no\nOption: "))

            # Pouzivatel chce poslat spravu
            if handler == 1:
                KPA_event.clear()
                message = str(input("Message you want to send: ")).encode()
                total_packets = math.ceil(len(message) / frag_size)
                header = create_header(1, total_packets)
                client_socket.sendto(header, address)

                data, addr = client_socket.recvfrom(1500)

                packet_type, packet_number, crc, received_data = get_header_data(data)

                if packet_type == 3:
                    send_message(message, total_packets, 1, frag_size, client_socket, address, error)

            # Pouzivatel chce poslat subor
            elif handler == 2:
                KPA_event.clear()
                file_name = str(input("File name you want to send: "))
                project_dir = int(input("File from working directory?\n\t[1] -> yes\n\t[2] -> no\nOption: "))
                temp = ""
                try:
                    file_size, file_path = 0, ''
                    if project_dir == 1:
                        file_size = os.path.getsize(file_name)
                        file_path = os.path.abspath(file_name)
                    elif project_dir == 2:
                        select_path = str(input("Select file path: "))
                        file_size = os.path.getsize(select_path + file_name)
                        file_path = os.path.abspath(select_path + file_name)
                        temp = file_name
                        file_name = file_path
                except FileNotFoundError:
                    print("Selected file not found")
                    continue

                if file_size > 2097152:
                    print("File too big")
                    continue
                if not file_path:
                    print("Could not find specified file")
                    continue

                print(f"File_size {file_size / 1000000} MB")
                print(file_path)

                file = open(file_name, "rb")
                file_read = file.read()
                total_packets = math.ceil(file_size / frag_size)
                if project_dir == 2:
                    file_name = temp
                file_name = file_name.encode()

                header = create_header(2, total_packets, 0, file_name)
                client_socket.sendto(header, address)
                data, addr = client_socket.recvfrom(1500)
                packet_type, packet_number, crc, recv_data = get_header_data(data)

                if packet_type == 3:
                    send_message(file_read, total_packets, 2, frag_size, client_socket, address, error)

            # Pouzivatel chce vymenit role
            elif handler == 3:
                KPA_event.clear()
                header = create_header(6, 0)
                client_socket.sendto(header, address)
                data, addr = client_socket.recvfrom(1500)
                packet_type, packet_number, crc, data = get_header_data(data)

                if packet_type == 3:
                    client_socket.close()
                    swap("client")

            # Pouzivatel chce ukoncit spojenie
            elif handler == 4:
                KPA_event.clear()
                end_event.set()
                end_connection(client_socket, address, thread)

        except socket.timeout:
            print("Connection timeout.")

    return 0


"""
Funkcia na poslanie spravy so vsetkymi potrebnymi parametrami
"""


def send_message(data, total_packets, packet_type, fragment_size, client_socket, dest_address, error):
    packets_sent = 0
    packet_number = 1
    wrong_packets = []
    # Vygenerovanie chybnych packetov
    if error == 1:
        number = int(input("Please select % of incorrect packets [1-99]: "))
        while number < 1 or number > 100:
            number = int(input("Please select % of incorrect packets [1-99]: "))

        number = math.ceil(total_packets * (number/100))
        for i in range(number):
            wrong_packets.append(random.randrange(0, total_packets))
        wrong_packets.sort()

    while True:
        # Ukoncovacia podmienka
        if packets_sent == total_packets:
            print("All packets transferred successfully")
            return

        to_send = data[:fragment_size]
        length = len(to_send)
        crc = zlib.crc32(to_send)

        # Generovanie chyby zmenou dat
        if len(wrong_packets) >= 1:
            if packet_type == 1 or packet_type == 2:
                if packets_sent == wrong_packets[0]:
                    if to_send[0] == b"A":
                        to_send += b'B'
                    else:
                        to_send += b'A'
                    to_send = to_send[::-1]
                    to_send = to_send[:length]
                    wrong_packets.pop(0)

        header = create_header(packet_type, packet_number, crc, to_send)

        client_socket.sendto(header, dest_address)

        new_type, addr = client_socket.recvfrom(1500)
        received_type, received_number, received_crc, received_data = get_header_data(new_type)

        # Ak prisiel ack
        if received_type == 3:
            packet_number += 1
            packets_sent += 1
            data = data[fragment_size:]


"""
Funkcia na pripojenie servra
"""


def server_connect():
    print("**********************   SERVER   **********************")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.settimeout(60)
        port = int(input("Select port on which you want to listen on: "))
        server_socket.bind(("", port))
        data, addr = server_socket.recvfrom(1500)
        packet_type, packet_number, crc, recv_data = get_header_data(data)
        if packet_type == 0:
            header = create_header(3, 0)
            server_socket.sendto(header, addr)
            print(f"\n\tConnection at address {addr[0]}")
        server(server_socket, addr)

    except socket.timeout:
        print("Connection Timeout")
        exit(0)


def server(server_socket, address):
    while True:
        try:
            server_socket.settimeout(20)

            data, addr = server_socket.recvfrom(1500)

            packet_type, total_number, crc, data = get_header_data(data)

            # Ak prisla sprava, ze klient chce poslat MESSAGE
            if packet_type == 1:
                print(f"\nPrepared to receive {total_number} packets")
                header = create_header(3, total_number)
                server_socket.sendto(header, address)
                receive_message(server_socket, address, packet_type, total_number)

            # Ak prisla sprava, ze klient chce poslat FILE
            elif packet_type == 2:
                directory = int(input("\nDo you want to save file in current directory?\n\t[1] -> yes\n\t[2] -> "
                                      "no\nOption: "))
                while directory != 1 and directory != 2:
                    print("\nIncorrect input.")
                    directory = int(input("\n\t[1] -> yes\n\t[2] -> no\nOption: "))
                file_name = data.decode()
                if directory == 2:
                    file_path = input("\nType full path where to save file: ")
                else:
                    file_dest = input("\nSelect directory where you want to save file: ")
                    file_path = os.path.dirname(os.path.abspath(file_name))
                    file_path = os.path.join(file_path, file_dest)
                    if not os.path.exists(file_path):
                        os.mkdir(file_path)

                print(file_path)
                file_path = file_path + "\\"
                file_path += file_name
                print(f"\nPrepared to receive {total_number} packets")

                header = create_header(3, total_number)
                server_socket.sendto(header, address)

                receive_message(server_socket, address, packet_type, total_number, file_path)

            # Ak prisla sprava, ze sa ma zacat keep alive
            elif packet_type == 5:
                header = create_header(3, 0)
                sys.stdout.write("\rKeep Alive counter: %d" % total_number)
                server_socket.sendto(header, address)

            # Ak prisla sprava, ze klient chce vymenit role
            elif packet_type == 6:
                header = create_header(3, 0)
                server_socket.sendto(header, address)

                server_socket.close()
                swap("server")

            # Ak prisla sprava, ze klient chce ukoncit spojenie
            elif packet_type == 7:
                header = create_header(3, total_number)
                server_socket.sendto(header, address)
                print("\n\tConnection closing...")
                server_socket.close()
                exit(0)

        except socket.timeout:
            server_socket.close()
            print("\nConnection timeout.")
            exit(0)


"""
Funkcia na prijatie spravy/suboru od klienta
"""


def receive_message(server_socket, address, packet_type, total_number, file_path=''):
    full = ''
    full_msg = []
    packets_received = 0

    while True:
        # Koncova podmienka
        if packets_received == total_number:
            print("\nAll packets received successfully")
            break

        data, addr = server_socket.recvfrom(1500)
        packet_type, packet_number, crc, message = get_header_data(data)
        received_crc = zlib.crc32(message)

        # Kontrola, ci data prisli v poriadku
        if received_crc == crc:
            packets_received += 1
            if packet_type == 2:
                full_msg.append(message)
            else:
                full += message.decode()

            header = create_header(3, packets_received)

            server_socket.sendto(header, address)
            print(f"Packet number {packet_number} | ACK | Size of data {len(message)}")
        else:
            header = create_header(4, packets_received)
            server_socket.sendto(header, address)
            print(f"Packet number {packet_number} | NACK | Size of data {len(message)}")

    # V pripade ze server obdrzal spravu tak ju vypise
    if packet_type == 1:
        print("\nMessage received:", full)
    # V pripade, ze obdrzal subor vypise absolutnu cestu k tomuto suboru
    else:
        file = open(file_path, "wb")
        for fragment in full_msg:
            file.write(fragment)
        file.close()

        print(f"\nFile received in location {file_path}")

    return


"""
Funkcia na vymenu roli
"""


def swap(socket_type):
    print("\n\tSwapping roles...\n\n")
    if socket_type == "client":
        server_connect()
    elif socket_type == "server":
        client_connect()


"""
Funkcia na udrzanie KEEP ALIVE spojenia
"""


def keep_alive(s, address, event, end_event):
    counter = 1
    while not end_event.is_set():
        if event.is_set():
            header = create_header(5, counter)
            s.sendto(header, address)
            data, addr = s.recvfrom(1500)
            packet_type, packet_number, crc, recv_data = get_header_data(data)

            if packet_type != 3:
                break
            counter += 1
            time.sleep(5)
        else:
            counter = 1
    return 0


"""
Funkcia na ukoncenie spojenia
"""


def end_connection(client_socket, address, thread):
    try:
        client_socket.settimeout(2)
        header = create_header(7, 0)
        client_socket.sendto(header, address)
        data, addr = client_socket.recvfrom(1500)
        packet_type, packet_number, crc, data = get_header_data(data)
        if packet_type == 3:
            print("\n\tConnection closing...")
            client_socket.close()
        else:
            print("\n\tConnection closing forcefully...")
            client_socket.close()
        thread.join()
        exit(0)
    except socket.timeout:
        print("\n\tConnection closing...")


choose_roles()

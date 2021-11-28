import socket
import sys
import threading
import os
import math
import time
import zlib
import struct # https://docs.python.org/3/library/struct.html

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


def create_header(packet_type, packet_number=0, crc=0, data=''.encode()):
    header = struct.pack("B", packet_type) + packet_number.to_bytes(3, byteorder="big") + crc.to_bytes(4, byteorder="big") +\
            struct.pack(f"{len(data)}s", data)
    return header


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
        client_socket, server_addr = client_connect()
        client(client_socket, server_addr)
    if role == SERVER:
        server_socket, addr = server_connect()
        server(server_socket, addr)

    return None


def client_menu():
    handler = int(input("Select option:"
                        "\n\t[1] -> Send message"
                        "\n\t[2] -> Send file"
                        "\n\t[3] -> Swap roles"
                        "\n\t[4] -> End connection"
                        "\nOption: "))
    return handler


def client_connect():
    while True:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = input("Input ip address you want to connect to: ")
        port = int(input("Select port you want to connect to: "))
        server_addr = (ip, port)
        client_socket.sendto(str.encode("0"), server_addr)
        client_socket.settimeout(60)
        data, addr = client_socket.recvfrom(1500)
        if data.decode() == "3":
            print(f"\n\tSuccessfully connected to address {addr}")
            return client_socket, server_addr
        else:
            continue


def client(client_socket, address):
    while True:
        frag_size = 1464
        handler = client_menu()
        error = 2

        if handler == 1 or handler == 2:
            frag_size = int(input("Select maximum fragment size: "))
            error = int(input("Send data with errors?\n\t[1] -> yes\n\t[2] -> no\nOption: "))

        if handler == 1:
            message = str(input("Message you want to send: ")).encode()
            total_packets = math.ceil(len(message) / frag_size)
            header = create_header(1, total_packets)
            client_socket.sendto(header, address)

            data, addr = client_socket.recvfrom(1500)

            packet_type, packet_number, crc, received_data = get_header_data(data)

            if packet_type == 3:
                send_message(message, total_packets, 1, frag_size, client_socket, address, error)

        elif handler == 2:
            file_name = str(input("File name you want to send: ")).encode()

        elif handler == 4:
            header = create_header(7, 0)
            client_socket.sendto(header, address)
            data, addr = client_socket.recvfrom(1500)
            packet_type, packet_number, crc, data = get_header_data(data)
            if packet_type == 3:
                print("Connection closing")
                client_socket.close()
            else:
                print("Connection closing forcefully")
                client_socket.close()
            break

    return 0


def send_message(data, total_packets, packet_type, fragment_size, client_socket, dest_address, error):
    packets_sent = 0
    packet_number = 1
    while True:
        if packets_sent == total_packets:
            print("All packets transferred successfully")
            return

        to_send = data[:fragment_size]
        crc = zlib.crc32(to_send)
        header = create_header(packet_type, packet_number, crc, to_send)

        client_socket.sendto(header, dest_address)

        new_type, addr = client_socket.recvfrom(1500)
        received_type, received_number, received_crc, received_data = get_header_data(new_type)

        if received_type == 3:
            packet_number += 1
            packets_sent += 1
            data = data[fragment_size:]


def server_connect():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(60)
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(ip)
    port = int(input("Select port on which you want to listen on: "))
    server_socket.bind((ip, port))
    data, addr = server_socket.recvfrom(1500)
    if data.decode() == "0":
        server_socket.sendto(str.encode("3"), addr)
        print(f"\n\tConnection at address {addr[0]}")
    return server_socket, addr


def server(server_socket, address):
    while True:

        data, addr = server_socket.recvfrom(1500)

        packet_type, total_number, crc, data = get_header_data(data)

        if packet_type == 1:
            print(f"Prepared to receive {total_number} packets")
            header = create_header(3, total_number)
            server_socket.sendto(header, address)
            receive_message(server_socket, address, packet_type, total_number)
        elif packet_type == 7:
            header = create_header(3, total_number)
            server_socket.sendto(header, address)
            print("Connection closing...")
            server_socket.close()
            break
    return 0


def receive_message(server_socket, address, packet_type, total_number):
    full = ''
    packets_received = 0

    while True:
        if packets_received == total_number:
            print("All packets received successfully")
            break

        data, addr = server_socket.recvfrom(1500)
        packet_type, packet_number, crc, message = get_header_data(data)
        received_crc = zlib.crc32(message)

        if received_crc == crc:
            packets_received += 1
            full += message.decode()

            header = create_header(3, packets_received)

            server_socket.sendto(header, address)
            print(f"Packet number {packet_number} | ACK")
        else:
            header = create_header(4, packets_received)
            server_socket.sendto(header, address)
            print(f"Packet number {packet_number} | NACK")

    print("Message received:", full)
    return


choose_roles()

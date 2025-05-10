#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author: ...with AI assist
# Description: TFTP Handshake Responder for Hikvision Devices
# This script listens for a specific handshake and responds by transferring files via TFTP.

import fcntl
import socket
import struct
import argparse
import os
import sys
import time
import platform

# Configuration constants
DEFAULT_HOST_IP = '192.168.1.128'  # Default IP to listen on
HANDSHAKE_PORT = 9978              # Port for handshake
RESPONSE_PORT = 9979               # Port for response to handshake
TFTP_PORT = 69                     # TFTP Port
HANDSHAKE_SIGNATURE = b'SWKH'      # Handshake signature
HANDSHAKE_RESPONSE = struct.pack('20s', HANDSHAKE_SIGNATURE)  # Response to the handshake

# TFTP opcodes
TFTP_OPCODE_RRQ = 1    # Read request
TFTP_OPCODE_DATA = 3    # Data packet
TFTP_OPCODE_ACK = 4     # Acknowledgment

# Default TFTP settings
DEFAULT_BLOCK_SIZE = 512  # Default block size for TFTP transfers
MAX_RETRIES = 20          # Max retries for receiving ACK
ACK_TIMEOUT = 5           # Timeout for waiting for ACK (in seconds)

# Network constants for Ethernet, IP, and UDP headers
ETH_HEADER_LEN = 14              # Ethernet header length
IP_HEADER_MIN_LEN = 20           # Minimum length of IP header
UDP_HEADER_LEN = 8               # Length of UDP header
ETH_TYPE_IPV4 = 0x0800           # EtherType for IPv4
IP_PROTO_UDP = 17                # Protocol number for UDP
IP_VERSION_IHL = 0x45            # IP version and IHL (IPv4 with 5 words header)
IP_FLAGS_DF = 0x4000             # IP Flags (Don't Fragment)
IP_TTL_HANDSHAKE = 128           # Time-to-Live for the handshake packet
IP_TTL_TFTP = 64                 # Time-to-Live for the TFTP packet

# Struct format strings for packing/unpacking headers
ETH_HEADER_FORMAT = '!6s6sH'      # Ethernet header format (MAC addresses and EtherType)
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'  # IP header format (various fields, source and destination IP)
UDP_HEADER_FORMAT = '!HHHH'       # UDP header format (source port, destination port, length, checksum)

def get_interface_ip(iface):
    """Returns the primary IPv4 address of the specified interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode())
        )
        ip = socket.inet_ntoa(info[20:24])
        return ip
    except (IOError, OSError):
        return None
    finally:
        s.close()

def get_default_interface(ip):
    """Determine the interface that has the given IP address."""
    try:
        for iface in os.listdir('/sys/class/net'):
            iface_ip = get_interface_ip(iface)
            if iface_ip == ip:
                return iface
        return None
    except Exception:
        return None

def calculate_checksum(data):
    """Calculate IP header checksum."""
    checksum = 0
    data = bytes(data) + (b'\x00' if len(data) % 2 else b'')
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    return ~checksum & 0xffff

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Hikvision TFTP handshake responder')
    parser.add_argument('--server-ip', default=DEFAULT_HOST_IP,
                        help=f'IP address to listen on (default: {DEFAULT_HOST_IP})')
    return parser.parse_args()

def create_socket(interface):
    """Create and bind a raw socket to the specified interface."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE_IPV4))
    sock.bind((interface, 0))  # Listen on interface
    return sock

def build_tftp_response(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, block_number, data):
    """Build TFTP data response packet."""
    udp_length = UDP_HEADER_LEN + 4 + len(data)

    ethernet_header = struct.pack(ETH_HEADER_FORMAT, src_mac, dst_mac, ETH_TYPE_IPV4)
    ip_header = struct.pack(IP_HEADER_FORMAT,
        IP_VERSION_IHL, 0x00, IP_HEADER_MIN_LEN + udp_length, 0x0000,
        IP_FLAGS_DF, IP_TTL_TFTP, IP_PROTO_UDP, 0,
        dst_ip, src_ip
    )
    udp_header = struct.pack(UDP_HEADER_FORMAT,
        dst_port, src_port, udp_length, 0
    )

    response = (
        ethernet_header +
        ip_header +
        udp_header +
        struct.pack('>H', TFTP_OPCODE_DATA) + struct.pack('>H', block_number) + data
    )

    # Calculate and set the IP checksum
    ip_part = response[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
    checksum = calculate_checksum(ip_part)
    response = response[:ETH_HEADER_LEN + 10] + struct.pack('!H', checksum) + response[ETH_HEADER_LEN + 12:]

    return response

def print_progress_bar(progress, total, bar_length=50):
    """Print progress bar in a single line with estimated remaining time."""
    progress_percent = (progress / total) * 100
    filled_length = int(progress_percent / 100 * bar_length)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    
    # Calculate remaining time
    elapsed_time = time.time() - start_time
    transfer_rate = progress / elapsed_time if elapsed_time > 0 else 0
    remaining_time = (total - progress) / transfer_rate if transfer_rate > 0 else 0

    # Print the progress bar
    print(f'\r[{bar}] {progress_percent:.2f}%  {progress}/{total} bytes  Remaining: {remaining_time:.2f}s', end='')

def main():
    args = parse_arguments()
    server_ip = args.server_ip

    # Determine the interface
    interface = get_default_interface(server_ip)
    if not interface:
        print("Unable to determine interface.")
        sys.exit(1)

    # Create socket
    sock = create_socket(interface)

    print(f"Server[{server_ip}] UDP socket on {interface} listening")
    print(f"To monitor traffic, run:\n  tcpdump -i {interface} -vv -X 'host {server_ip} and (port {HANDSHAKE_PORT} or port {RESPONSE_PORT} or port {TFTP_PORT})'\n")

    global start_time
    start_time = time.time()

    try:
        while True:
            packet, _ = sock.recvfrom(65535)

            # Process packet
            if len(packet) < ETH_HEADER_LEN: continue
            eth_header = packet[:ETH_HEADER_LEN]
            dst_mac, src_mac, eth_type = struct.unpack(ETH_HEADER_FORMAT, eth_header)
            if eth_type != ETH_TYPE_IPV4: continue

            # Check for valid IP header
            if len(packet) < ETH_HEADER_LEN + IP_HEADER_MIN_LEN: continue
            ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
            ip_ver_ihl, _, _, _, _, _, proto, _, src_ip, dst_ip = struct.unpack(IP_HEADER_FORMAT, ip_header)
            
            # Validate protocol and destination IP
            if proto != IP_PROTO_UDP or socket.inet_ntoa(dst_ip) != server_ip:
                continue

            # Parse UDP header
            ip_header_len = (ip_ver_ihl & 0x0F) * 4
            if len(packet) < ETH_HEADER_LEN + ip_header_len + UDP_HEADER_LEN: continue

            udp_start = ETH_HEADER_LEN + ip_header_len
            src_port, dst_port, udp_len, _ = struct.unpack(UDP_HEADER_FORMAT, packet[udp_start:udp_start + UDP_HEADER_LEN])
            if dst_port != HANDSHAKE_PORT:
                continue

            # Verify handshake signature
            data_start = udp_start + UDP_HEADER_LEN
            if len(packet) < data_start + len(HANDSHAKE_SIGNATURE): continue
            if packet[data_start:data_start + len(HANDSHAKE_SIGNATURE)] != HANDSHAKE_SIGNATURE:
                continue

            print(f"Device[{socket.inet_ntoa(src_ip)}:{HANDSHAKE_PORT}] test tftpserver")

            # Build and send handshake response
            response = (
                struct.pack(ETH_HEADER_FORMAT, src_mac, dst_mac, ETH_TYPE_IPV4) +
                struct.pack(IP_HEADER_FORMAT,
                    IP_VERSION_IHL, 0x00, 48, 0x0000,
                    IP_FLAGS_DF, IP_TTL_HANDSHAKE, IP_PROTO_UDP, 0,
                    dst_ip, src_ip
                ) +
                struct.pack(UDP_HEADER_FORMAT,
                    HANDSHAKE_PORT, RESPONSE_PORT, 28, 0
                ) +
                HANDSHAKE_RESPONSE
            )

            # Calculate and set IP checksum
            ip_part = response[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
            checksum = calculate_checksum(ip_part)
            response = response[:ETH_HEADER_LEN + 10] + struct.pack('!H', checksum) + response[ETH_HEADER_LEN + 12:]

            # Send response
            sock.send(response)
            print(f"Server[{server_ip}:{RESPONSE_PORT}] sent handshake to Device[{socket.inet_ntoa(src_ip)}:{dst_port}]")

            while True:
                # Receive and process TFTP packet
                tftp_packet, addr = sock.recvfrom(65536)

                # Parse TFTP request
                tftp_src_port, tftp_dst_port, udp_len, _ = struct.unpack(UDP_HEADER_FORMAT, tftp_packet[udp_start:udp_start + UDP_HEADER_LEN])
                if tftp_dst_port != TFTP_PORT:
                    continue

                # Check for Read Request opcode
                rrq_opcode = struct.unpack('>H', tftp_packet[udp_start + UDP_HEADER_LEN:udp_start + UDP_HEADER_LEN + 2])[0]

                if rrq_opcode == TFTP_OPCODE_RRQ:
                    data_start = udp_start + UDP_HEADER_LEN + 2
                    options_start = tftp_packet[data_start:].find(b'\x00')
                    if options_start != -1:
                        filename = tftp_packet[data_start:data_start + options_start]

                        print(f"Device[{socket.inet_ntoa(src_ip)}:{tftp_src_port}] Start file {filename.decode()} transmitting")

                        # Process the file transfer
                        block_number = 1  # Start with block 1
                        total_bytes = os.path.getsize(filename)
                        progress = 0  # Initialize progress
                        start_time = time.time()  # Track the start time

                        try:
                            with open(filename, 'rb') as f:
                                while True:
                                    data = f.read(DEFAULT_BLOCK_SIZE)
                                    
                                    if not data:
                                        # After file transfer is complete, calculate transfer time
                                        end_time = time.time()  # Current time (end time)
                                        transfer_duration = end_time - start_time  # Duration of transfer

                                        # Output completion info with duration
                                        response = build_tftp_response(
                                            dst_mac, src_mac,
                                            dst_ip, src_ip,
                                            TFTP_PORT, src_port,
                                            block_number, b''
                                        )
                                        sock.send(response)
                                        print(f"\nServer[{server_ip}:{TFTP_PORT}] Completed {filename.decode()} transmit. Time taken: {transfer_duration:.2f} seconds")

                                        while True:
                                            response_packet, _ = sock.recvfrom(65535)
                                            if len(response_packet) < ETH_HEADER_LEN + IP_HEADER_MIN_LEN + UDP_HEADER_LEN:
                                                continue

                                            udp_start = ETH_HEADER_LEN + (response_packet[ETH_HEADER_LEN] & 0x0F) * 4
                                            udp_hdr = response_packet[udp_start:udp_start + 8]
                                            tftp_src_port, tftp_dst_port, _, _ = struct.unpack('!HHHH', udp_hdr)
                                            if tftp_dst_port == HANDSHAKE_PORT and response_packet[udp_start + 8:udp_start + 8 + 4] == HANDSHAKE_SIGNATURE:
                                                print(f"Device[{socket.inet_ntoa(src_ip)}:{tftp_src_port}] System update completed!")
                                                sys.exit(0)  # Exit after receiving the SWKH signal

                                    # Send data block
                                    response = build_tftp_response(src_mac, dst_mac, src_ip, dst_ip, tftp_src_port, tftp_dst_port, block_number, data)
                                    sock.send(response)
                                    progress += len(data)

                                    # Print progress bar
                                    print_progress_bar(progress, total_bytes)

                                    sock.settimeout(ACK_TIMEOUT)
                                    ack_packet, _ = sock.recvfrom(65535)

                                    # Increment block number
                                    block_number = (block_number + 1) % 65536

                        except FileNotFoundError:
                            print(f"Error: File {filename.decode()} not found")
                        except Exception as e:
                            print(f"File transfer error: {str(e)}")

    except KeyboardInterrupt:
        print("\nStopped by user")
    finally:
        sock.close()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import socket
import struct
import argparse
import os

# Configuration
DEFAULT_HOST_IP = '192.168.1.128'
DEFAULT_INTERFACE = 'wlan0'
DEFAULT_FILE = 'digicap.dav'
HANDSHAKE_PORT = 9978
RESPONSE_PORT = 9979
TFTP_PORT = 69
HANDSHAKE_SIGNATURE = b'SWKH'
HANDSHAKE_RESPONSE = struct.pack('20s', HANDSHAKE_SIGNATURE)

# TFTP constants
TFTP_OPCODE_RRQ = 1
TFTP_OPCODE_DATA = 3
TFTP_OPCODE_ACK = 4
DEFAULT_BLOCK_SIZE = 512
MAX_RETRIES = 20
ACK_TIMEOUT = 5

# Network constants
ETH_HEADER_LEN = 14
IP_HEADER_MIN_LEN = 20
UDP_HEADER_LEN = 8
ETH_TYPE_IPV4 = 0x0800
IP_PROTO_UDP = 17
IP_VERSION_IHL = 0x45
IP_FLAGS_DF = 0x4000
IP_TTL_HANDSHAKE = 128
IP_TTL_TFTP = 64

# Struct format strings
ETH_HEADER_FORMAT = '!6s6sH'
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'
UDP_HEADER_FORMAT = '!HHHH'

def calculate_checksum(data):
    """Calculate IP header checksum"""
    checksum = 0
    data = bytes(data) + (b'\x00' if len(data) % 2 else b'')
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    return ~checksum & 0xffff

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Hikvision TFTP handshake responder')
    parser.add_argument('--host', default=DEFAULT_HOST_IP,
                        help=f'IP address to listen on (default: {DEFAULT_HOST_IP})')
    parser.add_argument('--interface', default=DEFAULT_INTERFACE,
                        help=f'Network interface (default: {DEFAULT_INTERFACE})')
    parser.add_argument('--file', default=DEFAULT_FILE,
                        help='File to serve via TFTP')
    return parser.parse_args()

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

    ip_part = response[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
    checksum = calculate_checksum(ip_part)
    response = response[:ETH_HEADER_LEN + 10] + struct.pack('!H', checksum) + response[ETH_HEADER_LEN + 12:]

    return response

def parse_ack_packet(packet, expected_src_port, host_ip):
    """Parse and validate ACK packet"""
    if len(packet) < ETH_HEADER_LEN + IP_HEADER_MIN_LEN + UDP_HEADER_LEN + 4:
        return None

    eth_header = packet[:ETH_HEADER_LEN]
    _, _, eth_type = struct.unpack(ETH_HEADER_FORMAT, eth_header)
    if eth_type != ETH_TYPE_IPV4:
        return None

    ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
    ip_ver_ihl, _, _, _, _, _, proto, _, src_ip, dst_ip = struct.unpack(IP_HEADER_FORMAT, ip_header)
    if proto != IP_PROTO_UDP or socket.inet_ntoa(dst_ip) != host_ip:
        return None

    ip_header_len = (ip_ver_ihl & 0x0F) * 4
    udp_start = ETH_HEADER_LEN + ip_header_len

    udp_header = packet[udp_start:udp_start + UDP_HEADER_LEN]
    src_port, dst_port, udp_len, _ = struct.unpack(UDP_HEADER_FORMAT, udp_header)
    if dst_port != TFTP_PORT or src_port != expected_src_port:
        return None

    tftp_start = udp_start + UDP_HEADER_LEN
    if len(packet) < tftp_start + 4:
        return None

    opcode, block_num = struct.unpack('>HH', packet[tftp_start:tftp_start + 4])
    if opcode != TFTP_OPCODE_ACK:
        return None

    return block_num

def main():
    args = parse_arguments()
    
    # Setup RAW socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE_IPV4))
    sock.bind((args.interface, 0))
    
    print(f"Listening for Hikvision handshake on {args.host}:{HANDSHAKE_PORT}")
    print("Press Ctrl+C to stop...")

    try:
        while True:
            packet, _ = sock.recvfrom(65535)
            
            if len(packet) < ETH_HEADER_LEN: continue
            eth_header = packet[:ETH_HEADER_LEN]
            dst_mac, src_mac, eth_type = struct.unpack(ETH_HEADER_FORMAT, eth_header)
            if eth_type != ETH_TYPE_IPV4: continue

            if len(packet) < ETH_HEADER_LEN + IP_HEADER_MIN_LEN: continue
            ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
            ip_ver_ihl, _, _, _, _, _, proto, _, src_ip, dst_ip = struct.unpack(IP_HEADER_FORMAT, ip_header)
            
            if proto != IP_PROTO_UDP or socket.inet_ntoa(dst_ip) != args.host:
                continue

            ip_header_len = (ip_ver_ihl & 0x0F) * 4
            if len(packet) < ETH_HEADER_LEN + ip_header_len + UDP_HEADER_LEN: continue

            udp_start = ETH_HEADER_LEN + ip_header_len
            src_port, dst_port, udp_len, _ = struct.unpack(UDP_HEADER_FORMAT, packet[udp_start:udp_start + UDP_HEADER_LEN])
            
            if dst_port != HANDSHAKE_PORT:
                continue

            data_start = udp_start + UDP_HEADER_LEN
            if len(packet) < data_start + len(HANDSHAKE_SIGNATURE): continue
            if packet[data_start:data_start + len(HANDSHAKE_SIGNATURE)] != HANDSHAKE_SIGNATURE:
                continue

            print(f"Valid handshake from {socket.inet_ntoa(src_ip)}:{src_port}")

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

            ip_part = response[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_MIN_LEN]
            checksum = calculate_checksum(ip_part)
            response = response[:ETH_HEADER_LEN + 10] + struct.pack('!H', checksum) + response[ETH_HEADER_LEN + 12:]

            sock.send(response)
            print("Handshake response sent")

            # Now listen for TFTP requests
            block_number = 1

            while True:
                tftp_packet, addr = sock.recvfrom(65536)

                udp_start = ETH_HEADER_LEN + ((ip_ver_ihl & 0x0F) * 4)
                tftp_src_port, tftp_dst_port, udp_len, _ = struct.unpack(UDP_HEADER_FORMAT, tftp_packet[udp_start:udp_start + UDP_HEADER_LEN])
                if tftp_dst_port != TFTP_PORT:
                    continue

                rrq_opcode = struct.unpack('>H', tftp_packet[udp_start + UDP_HEADER_LEN:udp_start + UDP_HEADER_LEN + 2])[0]
                if rrq_opcode == TFTP_OPCODE_RRQ:
                    data_start = udp_start + UDP_HEADER_LEN + 2
                    options_start = tftp_packet[data_start:].find(b'\x00')
                    if options_start != -1:
                        filename = tftp_packet[data_start:data_start + options_start]
                        options = tftp_packet[data_start + options_start + 1:-1]
                        print(f"Received read request for file: {filename.decode()}")
                        print(f"Options: {options.decode()}")

                        blksize = DEFAULT_BLOCK_SIZE
                        tsize = 0
                        options_list = options.split(b'\x00')
                        for i in range(0, len(options_list) - 1, 2):
                            if options_list[i] == b'blksize':
                                blksize = int(options_list[i + 1])
                            elif options_list[i] == b'tsize':
                                tsize = int(options_list[i + 1])

                        print(f"Block size: {blksize}, Total size: {tsize}")

                        try:
                            with open(args.file, 'rb') as f:
                                file_size = os.path.getsize(args.file)
                                bytes_sent = 0
                                block_number = 1
                                client_port = src_port
                                client_ip = src_ip

                                while True:
                                    data = f.read(blksize)
                                    
                                    if not data:
                                        response = build_tftp_response(
                                            dst_mac, src_mac,
                                            dst_ip, src_ip,
                                            TFTP_PORT, client_port,
                                            block_number, b''
                                        )
                                        sock.send(response)
                                        print("Sent final empty block")
                                        break

                                    response = build_tftp_response(src_mac, dst_mac, src_ip, dst_ip, tftp_src_port, tftp_dst_port, block_number, data)
                                    sock.send(response)
                                    bytes_sent += len(data)

                                    progress = (bytes_sent / file_size) * 100
                                    print(f"Progress: {progress:.2f}%")

                                    ack_received = False
                                    for retry in range(MAX_RETRIES):
                                        try:
                                            sock.settimeout(ACK_TIMEOUT)
                                            ack_packet, _ = sock.recvfrom(65535)
                                            ack_block = parse_ack_packet(ack_packet, tftp_src_port, args.host)
                                            
                                            if ack_block == block_number:
                                                ack_received = True
                                                break
                                            elif ack_block is not None:
                                                print(f"Received ACK for wrong block {ack_block}")
                                        except socket.timeout:
                                            print(f"Timeout waiting for ACK (retry {retry + 1})")
                                            sock.send(response)
                                        except Exception as e:
                                            print(f"Error processing ACK: {e}")

                                    if not ack_received:
                                        print("Max retries exceeded, aborting transfer")
                                        break

                                    block_number = (block_number + 1) % 65536

                                print("TFTP transfer complete")

                        except FileNotFoundError:
                            print(f"Error: File {args.file} not found")
                        except Exception as e:
                            print(f"File transfer error: {str(e)}")

    except KeyboardInterrupt:
        print("\nStopped by user")
    finally:
        sock.close()

if __name__ == '__main__':
    main()

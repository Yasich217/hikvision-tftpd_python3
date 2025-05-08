#!/usr/bin/env python3
import socket
import struct
import argparse

# Configuration (default values)
DEFAULT_HOST_IP = '192.168.1.128'
DEFAULT_INTERFACE = 'wlan0'
HANDSHAKE_PORT = 9978
RESPONSE_PORT = 9979
TFTP_PORT = 69
HANDSHAKE_SIGNATURE = b'SWKH'
HANDSHAKE_RESPONSE = struct.pack('20s', HANDSHAKE_SIGNATURE)

# Network constants
ETH_HEADER_LEN = 14
IP_HEADER_MIN_LEN = 20
UDP_HEADER_LEN = 8
ETH_TYPE_IPV4 = 0x0800
IP_PROTO_UDP = 17
IP_VERSION_IHL = 0x45  # IPv4, 20 byte header
IP_FLAGS_DF = 0x4000   # Don't Fragment
IP_TTL = 128

# Struct format strings
ETH_HEADER_FORMAT = '!6s6sH'        # MAC dst, MAC src, EtherType
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'  # IP header fields
UDP_HEADER_FORMAT = '!HHHH'         # src_port, dst_port, length, checksum

def calculate_checksum(data):
    """Calculate IP header checksum"""
    checksum = 0
    data = bytes(data) + (b'\x00' if len(data) % 2 else b'')  # Pad to even length
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
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
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Setup RAW socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE_IPV4))
    sock.bind((args.interface, 0))
    
    print(f"Listening for Hikvision handshake on {args.interface} {args.host}:{HANDSHAKE_PORT}")
    print(f"To monitor traffic, run:")
    print(f"tcpdump -i {args.interface} -vv -X 'host {args.host} and (port {HANDSHAKE_PORT} or port {RESPONSE_PORT} or port {TFTP_PORT})'")
    print("Press Ctrl+C to stop...")

    try:
        while True:
            packet, _ = sock.recvfrom(65535)
            
            # Parse Ethernet header
            if len(packet) < ETH_HEADER_LEN: continue
            eth_header = packet[:ETH_HEADER_LEN]
            dst_mac, src_mac, eth_type = struct.unpack(ETH_HEADER_FORMAT, eth_header)
            if eth_type != ETH_TYPE_IPV4: continue  # IPv4 only

            # Parse IP header
            if len(packet) < ETH_HEADER_LEN + IP_HEADER_MIN_LEN: continue
            ip_header = packet[ETH_HEADER_LEN:ETH_HEADER_LEN+IP_HEADER_MIN_LEN]
            ip_ver_ihl, _, _, _, _, _, proto, _, src_ip, dst_ip = struct.unpack(IP_HEADER_FORMAT, ip_header)
            
            # Check protocol and destination IP
            if proto != IP_PROTO_UDP or socket.inet_ntoa(dst_ip) != args.host:
                continue

            # Calculate IP header length
            ip_header_len = (ip_ver_ihl & 0x0F) * 4
            if len(packet) < ETH_HEADER_LEN + ip_header_len + UDP_HEADER_LEN: continue

            # Parse UDP header
            udp_start = ETH_HEADER_LEN + ip_header_len
            src_port, dst_port, _, _ = struct.unpack(UDP_HEADER_FORMAT, packet[udp_start:udp_start+UDP_HEADER_LEN])
            
            # Check destination port
            if dst_port != HANDSHAKE_PORT:
                continue

            # Verify handshake signature
            data_start = udp_start + UDP_HEADER_LEN
            if len(packet) < data_start + len(HANDSHAKE_SIGNATURE): continue
            if packet[data_start:data_start+len(HANDSHAKE_SIGNATURE)] != HANDSHAKE_SIGNATURE:
                continue

            print(f"Valid handshake from {socket.inet_ntoa(src_ip)}:{src_port}")

            # Build response packet
            response = (
                # Ethernet header (swap MAC addresses)
                struct.pack(ETH_HEADER_FORMAT, src_mac, dst_mac, ETH_TYPE_IPV4) +
                
                # IP header
                struct.pack(IP_HEADER_FORMAT,
                    IP_VERSION_IHL,  # Version/IHL
                    0x00,           # TOS
                    48,             # Total Length
                    0x0000,         # Identification
                    IP_FLAGS_DF,     # Flags: Don't Fragment
                    IP_TTL,         # TTL
                    IP_PROTO_UDP,   # Protocol
                    0,              # Checksum (will fill later)
                    dst_ip,         # Source IP
                    src_ip          # Destination IP
                ) +
                
                # UDP header
                struct.pack(UDP_HEADER_FORMAT,
                    HANDSHAKE_PORT,  # Source Port
                    RESPONSE_PORT,   # Destination Port
                    28,             # Length
                    0               # Checksum
                ) +
                
                # Payload
                HANDSHAKE_RESPONSE
            )

            # Calculate and set IP checksum
            ip_part = response[ETH_HEADER_LEN:ETH_HEADER_LEN+IP_HEADER_MIN_LEN]
            checksum = calculate_checksum(ip_part)
            response = response[:ETH_HEADER_LEN+10] + struct.pack('!H', checksum) + response[ETH_HEADER_LEN+12:]

            # Send response
            sock.send(response)
            print("Handshake response sent")

    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        sock.close()

if __name__ == '__main__':
    main()
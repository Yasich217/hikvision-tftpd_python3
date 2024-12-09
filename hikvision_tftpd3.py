#!/usr/bin/env python3
"""
Unbrick a Hikvision device. See README.md for usage information.
"""

from __future__ import division

__author__ = 'Simon Beehre'
__license__ = 'MIT'
__email__ = 'sbeehre@gmail.com'

import argparse
import errno
import os
import select
import socket
import struct
import sys
import time

HANDSHAKE_BYTES = struct.pack('20s', b'SWKH')
_HANDSHAKE_SERVER_PORT = 9978
_TFTP_SERVER_PORT = 69
_TIME_FMT = '%c'
_DEFAULT_BLOCK_SIZE = 512


class Error(Exception): pass


class Server:
    # See https://tools.ietf.org/html/rfc1350
    _TFTP_OPCODE_RRQ = 1
    _TFTP_OPCODE_DATA = 3
    _TFTP_OPCODE_ACK = 4
    _TFTP_OPCODE_OACK = 6
    _TFTP_ACK_PREFIX = struct.pack('>h', _TFTP_OPCODE_ACK)

    def __init__(self, handshake_addr, tftp_addr, filename, file_contents):
        self._file_contents = file_contents
        self._filename = filename
        self._tftp_rrq_prefix = (struct.pack('>h', self._TFTP_OPCODE_RRQ) +
                                 filename.encode('utf-8') + b'\x00')
        self._tftp_blksize_option = b'blksize\x00'
        self._handshake_sock = self._bind(handshake_addr)
        self._tftp_sock = self._bind(tftp_addr)
        self._set_block_size(_DEFAULT_BLOCK_SIZE)

    def _bind(self, addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(addr)
        except socket.error as e:
            if e.errno == errno.EADDRNOTAVAIL:
                raise Error(
                    ('Address %s:%d not available.\n\n'
                     'Try running:\n'
                     'linux$ sudo ifconfig eth0:0 %s\n'
                     'osx$   sudo ifconfig en0 alias %s '
                     '255.255.255.0\n\n'
                     '(adjust eth0 or en0 to taste. see "ifconfig -a" output)')
                    % (addr[0], addr[1], addr[0], addr[0]))
            if e.errno == errno.EADDRINUSE:
                raise Error(
                    ('Address %s:%d in use.\n'
                     'Make sure no other TFTP server is running.') % addr)
            if e.errno == errno.EACCES:
                raise Error(('No permission to bind to %s:%d.\n'
                             'Try running with sudo.') % addr)
            raise
        return sock

    def _set_block_size(self, block_size):
        print(f'Setting block size to {block_size}')
        self._block_size = block_size
        self._total_blocks = ((len(self._file_contents) + self._block_size)
                              // self._block_size)
        print(f'Serving {len(self._file_contents)}-byte {self._filename} (block size {self._block_size}, {self._total_blocks} blocks)')

    def _check_total_block_limit(self):
        if self._total_blocks > 65535:
            raise Error('File is too big to serve with %d-byte blocks.'
                        % self._block_size)

    def _parse_options(self, pkt):
        pkt_options = pkt.split(self._tftp_rrq_prefix)[1]
        options_list = pkt_options.split(b'\x00')[1:]
        options = {}
        for i in range(0, len(options_list) - 1, 2):
            options[options_list[i].decode('utf-8')] = options_list[i + 1].decode('utf-8')
        print(f'read request options: {options}')
        return options

    def close(self):
        self._handshake_sock.close()
        self._tftp_sock.close()

    def run_forever(self):
        while True:
            self._iterate()

    def _iterate(self):
        r, _, _ = select.select(
            [self._handshake_sock, self._tftp_sock], [], [])
        if self._handshake_sock in r:
            self._handshake_read()
        if self._tftp_sock in r:
            self._tftp_read()

    def _handshake_read(self):
        pkt, addr = self._handshake_sock.recvfrom(len(HANDSHAKE_BYTES))
        now = time.strftime(_TIME_FMT)
        if pkt == HANDSHAKE_BYTES:
            self._handshake_sock.sendto(pkt, addr)
            print(f'{now}: Replied to magic handshake request.')
        else:
            print(f'{now}: received unexpected handshake bytes {pkt.hex()} from {addr[0]}:{addr[1]}')

    def _tftp_read(self):
        pkt, addr = self._tftp_sock.recvfrom(65536)
        now = time.strftime(_TIME_FMT)
        if pkt.startswith(self._tftp_rrq_prefix):
            options = self._parse_options(pkt)
            if 'blksize' in options:
                self._set_block_size(int(options['blksize']))
                print(f'{now}: sending options ack')
                self._tftp_options_ack(addr)
                return
            self._check_total_block_limit()
            print(f'{now}: starting transfer')
            self._tftp_maybe_send(0, addr)
        elif pkt.startswith(self._TFTP_ACK_PREFIX):
            block, = struct.unpack('>H', pkt[len(self._TFTP_ACK_PREFIX):])
            self._tftp_maybe_send(block, addr)
        else:
            print(f'{now}: received unexpected tftp bytes {pkt.hex()} from {addr[0]}:{addr[1]}')

    def _tftp_options_ack(self, addr):
        self._check_total_block_limit()
        pkt = (struct.pack('>H', self._TFTP_OPCODE_OACK) + b'blksize\x00' + str(self._block_size).encode('utf-8') + b'\x00')
        self._tftp_sock.sendto(pkt, addr)

    def _tftp_maybe_send(self, prev_block, addr):
        block = prev_block + 1
        start_byte = prev_block * self._block_size
        if start_byte > len(self._file_contents):
            print(f'{time.strftime(_TIME_FMT)}: done!')
            if self._block_size != _DEFAULT_BLOCK_SIZE:
                self._set_block_size(_DEFAULT_BLOCK_SIZE)
            return
        block_data = self._file_contents[start_byte:start_byte + self._block_size]
        pkt = (struct.pack('>hH', self._TFTP_OPCODE_DATA, block) + block_data)
        self._tftp_sock.sendto(pkt, addr)
        _progress_width = 53
        print(f'{time.strftime(_TIME_FMT)}: {block:5d} / {self._total_blocks:5d} [{"#" * (_progress_width * block // self._total_blocks):{_progress_width}s}]')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--filename', default='digicap.dav',
                        help='file to serve; used both to read from the local '
                             'disk and for the filename to expect from client')
    parser.add_argument('--server-ip', default='192.0.0.128',
                        help='IP address to serve from.')
    args = parser.parse_args()
    try:
        file_contents = open(args.filename, mode='rb').read()
    except IOError as e:
        print(f'Error: can\'t read {args.filename}')
        if e.errno == errno.ENOENT:
            print('Please download/move it to the current working directory.')
            sys.exit(1)
        raise

    try:
        server = Server((args.server_ip, _HANDSHAKE_SERVER_PORT),
                        (args.server_ip, _TFTP_SERVER_PORT),
                        args.filename, file_contents)
    except Error as e:
        print(f'Error: {e}')
        sys.exit(1)

    server.run_forever()

#!/usr/bin/env python3
"""Reference server for the OffByWon 2.0 binary quickstart protocol."""

import argparse
import socket
import socketserver
import struct


REQUEST_HEADER = struct.Struct('<4sBBHII')
RESPONSE_HEADER = struct.Struct('<4sBII')
REQUEST_MAGIC = b'OBW2'
RESPONSE_MAGIC = b'OBR2'
MAX_PAYLOAD = 65536

STATUS_OK = 0
STATUS_BAD_MAGIC = 1
STATUS_BAD_VERSION = 2
STATUS_LENGTH_TOO_LARGE = 3
STATUS_TRUNCATED_PAYLOAD = 4
STATUS_UNSUPPORTED_OPCODE = 5


def recv_exact(sock, size):
    """Read up to size bytes, stopping early when the peer closes."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def build_response(status, request_id, payload=b''):
    return RESPONSE_HEADER.pack(
        RESPONSE_MAGIC,
        status,
        request_id,
        len(payload),
    ) + payload


class BinaryRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2.0)
        try:
            header = recv_exact(self.request, REQUEST_HEADER.size)
            if len(header) != REQUEST_HEADER.size:
                return

            magic, version, opcode, _flags, request_id, payload_length = (
                REQUEST_HEADER.unpack(header)
            )

            if magic != REQUEST_MAGIC:
                response = build_response(STATUS_BAD_MAGIC, request_id)
            elif version != 1:
                response = build_response(STATUS_BAD_VERSION, request_id)
            elif payload_length > MAX_PAYLOAD:
                response = build_response(STATUS_LENGTH_TOO_LARGE, request_id)
            else:
                payload = recv_exact(self.request, payload_length)
                if len(payload) != payload_length:
                    response = build_response(STATUS_TRUNCATED_PAYLOAD, request_id)
                elif opcode == 1:
                    response = build_response(STATUS_OK, request_id, payload)
                elif opcode == 2:
                    response = build_response(STATUS_OK, request_id, payload[::-1])
                else:
                    response = build_response(STATUS_UNSUPPORTED_OPCODE, request_id)

            self.request.sendall(response)
        except (ConnectionError, OSError, socket.timeout, struct.error):
            return


class BinaryServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(
        description='Reference target for the OffByWon binary quickstart',
    )
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9000)
    args = parser.parse_args()

    with BinaryServer((args.host, args.port), BinaryRequestHandler) as server:
        print('[*] Binary quickstart target listening on {}:{}'.format(
            args.host,
            args.port,
        ))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\n[*] Target stopped')


if __name__ == '__main__':
    main()

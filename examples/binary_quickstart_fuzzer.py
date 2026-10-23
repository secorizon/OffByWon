#!/usr/bin/env python3
"""Minimal OffByWon 2.0 fuzzer for the binary quickstart protocol."""

import argparse
import socket
import struct

from offbywon import Field, FieldType, Framework, Packet


RESPONSE_HEADER = struct.Struct('<4sBII')
RESPONSE_MAGIC = b'OBR2'
MAX_RESPONSE_PAYLOAD = 65536

STATUS_NAMES = {
    0: 'ok',
    1: 'bad_magic',
    2: 'bad_version',
    3: 'length_too_large',
    4: 'truncated_payload',
    5: 'unsupported_opcode',
}


class BinaryRequest(Packet):
    """Little-endian request with an automatically resolved payload length."""

    fields = [
        Field('magic', FieldType.BYTES, b'OBW2', size=4, fuzz=False),
        Field('version', FieldType.BYTE, 1, fuzz=False),
        Field('opcode', FieldType.BYTE, 1),
        Field('flags', FieldType.WORD, 0),
        Field('request_id', FieldType.DWORD, 0x11223344),
        Field(
            'payload_length',
            FieldType.LENGTH,
            target='payload',
            size_type=FieldType.DWORD,
        ),
        Field('payload', FieldType.BYTES, b'\x10\x20\x30\x40'),
    ]


def recv_exact(sock, size):
    """Read exactly size bytes or raise when the response is incomplete."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError('response ended with {} bytes missing'.format(remaining))
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def exchange(host, port, packet, timeout):
    """Send one binary request and decode its framed binary response."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(packet)
        sock.shutdown(socket.SHUT_WR)

        header = recv_exact(sock, RESPONSE_HEADER.size)
        magic, status, request_id, payload_length = RESPONSE_HEADER.unpack(header)
        if magic != RESPONSE_MAGIC:
            raise ValueError('invalid response magic {!r}'.format(magic))
        if payload_length > MAX_RESPONSE_PAYLOAD:
            raise ValueError('response payload is too large: {}'.format(payload_length))
        payload = recv_exact(sock, payload_length)
        return status, request_id, payload


def response_summary(response):
    status, request_id, payload = response
    return 'status={}({}) id=0x{:08x} payload={}'.format(
        status,
        STATUS_NAMES.get(status, 'unknown'),
        request_id,
        payload[:16].hex() + ('...' if len(payload) > 16 else ''),
    )


def main():
    parser = argparse.ArgumentParser(
        description='OffByWon 2.0 five-minute binary fuzzer example',
    )
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--iterations', type=int, default=25)
    parser.add_argument(
        '--mode',
        choices=['field', 'length', 'byteflip', 'blind', 'combined', 'full'],
        default='field',
    )
    parser.add_argument(
        '--field',
        choices=['opcode', 'flags', 'request_id'],
        default='request_id',
    )
    parser.add_argument('--seed', type=int)
    parser.add_argument('--timeout', type=float, default=1.0)
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error('--iterations must be at least 1')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')

    framework = Framework(verbose=False, seed=args.seed)
    values = {
        'opcode': 1,
        'flags': 0,
        'request_id': 0x11223344,
        'payload': b'\x10\x20\x30\x40',
    }

    clean = framework.build_clean(BinaryRequest, values)
    try:
        baseline = exchange(args.host, args.port, clean, args.timeout)
    except (ConnectionError, OSError, ValueError, struct.error) as exc:
        parser.error('clean baseline exchange failed: {}'.format(exc))

    expected = (0, values['request_id'], values['payload'])
    if baseline != expected:
        parser.error('unexpected clean baseline: {}'.format(response_summary(baseline)))

    print('[+] Baseline OK: {}'.format(response_summary(baseline)))

    structured_modes = {'field', 'combined', 'full'}
    byteflip_modes = {'byteflip', 'combined', 'full'}

    for case_number in range(1, args.iterations + 1):
        target_fields = None
        fuzz_count = None
        if args.mode in structured_modes:
            target_fields = [args.field]
            fuzz_count = 1
        elif args.mode == 'length':
            fuzz_count = 1

        packet, info = framework.build(
            BinaryRequest,
            mode=args.mode,
            values=values,
            fields=target_fields,
            fuzz_count=fuzz_count,
            byteflip_count=1 if args.mode in byteflip_modes else None,
        )

        try:
            response = exchange(args.host, args.port, packet, args.timeout)
            result = response_summary(response)
        except (ConnectionError, OSError, ValueError, struct.error) as exc:
            result = '{}: {}'.format(type(exc).__name__, exc)

        strategies = [mutation.strategy for mutation in info.mutations]
        if info.byteflips:
            strategies.append('byteflip')
        print(
            '[{:03d}] seed={} size={} mutations={} response={}'.format(
                case_number,
                info.seed,
                len(packet),
                ','.join(strategies) or 'none',
                result,
            )
        )


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
QUIC Initial Packet Fuzzer
==========================

A protocol fuzzer for QUIC v1 (RFC 9000) Initial packets, built on the OffByWon
declarative fuzzing framework. Designed to exercise the QUIC and TLS parsing
paths of a server such as quinn (https://github.com/quinn-rs/quinn).

Why this is more than a "blast random UDP" fuzzer
-------------------------------------------------
A QUIC Initial packet is AEAD-protected (RFC 9001). The keys are derived from
the client's Destination Connection ID using a fixed Initial salt, so anyone can
encrypt/decrypt Initial packets - but a server drops any datagram whose AEAD tag
or header-protection mask is wrong *before* it ever parses a single frame. A
fuzzer that mutates bytes blindly therefore never gets past the crypto gate and
only ever tests the AEAD verifier.

This fuzzer keeps the cryptography correct by default. It mutates the *structure*
(connection-ID lengths, token length, the length varint, CRYPTO frame
offset/length varints, TLS ClientHello length vectors, QUIC transport
parameters) using OffByWon's declarative packet definitions, then re-encrypts so
the mutated packet passes AEAD and reaches quinn's frame parser and rustls'
ClientHello parser - which is where Rust panics / DoS conditions live.

Two fuzzing surfaces
--------------------
  1. Cleartext long header (parsed BEFORE decryption): version, DCID len, DCID,
     SCID len, SCID, token length varint, length varint, packet number.
     These are the classic off-by-one targets and are reachable even with a
     broken AEAD tag.
  2. Protected payload (reached only AFTER successful decryption): QUIC frames
     (CRYPTO offset/length varints, frame-type varints, ACK ranges), the TLS
     ClientHello (3-byte/2-byte length vectors, extension lengths), and the
     QUIC transport parameters extension. Packets targeting this surface are
     always correctly re-encrypted.

Every layer is described with OffByWon Packet/Field definitions (VARINT, LENGTH,
OFFSET, BYTES, RESERVED...) and built with Framework.build(mode=...), exactly as
documented in the framework README. The RFC 9001 crypto layer is implemented
inline (mirroring how the LDAP example implements NTLM crypto) and is validated
against the RFC 9001 Appendix A worked example on startup with --self-test.

OffByWon Fuzzing Framework
Author: Laurent Gaffié
Website: https://secorizon.com
Twitter: @secorizon

Usage:
    # Validate the crypto layer against RFC 9001 Appendix A (no network)
    python3 quic_initial_fuzzer.py --self-test

    # Connectivity / baseline check: send one clean valid Initial, expect a reply
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 --dry-run -n1

    # Structured field fuzzing of the cleartext long header
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 -f --fuzz-target header

    # Length/offset mismatch fuzzing of the CRYPTO frame (re-encrypted)
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 -f --fuzz-len --fuzz-target crypto_frame

    # Fuzz the TLS ClientHello length vectors (reaches rustls parser)
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 -f --fuzz-target tls

    # Fuzz QUIC transport parameters (reaches quinn's TP parser)
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 -f --fuzz-target transport_params

    # Everything, combined field + byteflip, forever
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 -f --combined --fuzz-target all

    # Exactly one structured mutation plus one final-datagram byteflip
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 --combined \
        --fuzz-target all --fuzz-count 1 --byteflip-count 1

    # Blind byte corruption of the final datagram (tests the AEAD gate itself)
    python3 quic_initial_fuzzer.py -s ::1 -p 4433 --blind
"""

import socket
import struct
import os
import sys
import time
import argparse
import random
from typing import Optional, Tuple, List, Dict, Any

# =============================================================================
# IMPORT THE OFFBYWON FRAMEWORK
# =============================================================================
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offbywon import (
    Framework, Packet, Field, Marker, FieldType, FuzzMode,
    get_fuzz_integer, get_fuzz_buffer,
    VARINT_BOUNDARIES, LENGTH_DELTAS, COUNT_VALUES, OFFSET_CORRUPTIONS,
)

# =============================================================================
# CRYPTOGRAPHY (RFC 9001 Initial protection)
# =============================================================================
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


# =============================================================================
# BANNER
# =============================================================================

BANNER = r"""
   ____  __  __ ____        _       __
  / __ \/ /_/ _/ __ )__  __| |     / /___  ____
 / / / / __/ /_/ __  / / / / | /| / / __ \/ __ \
/ /_/ / /_/ __/ /_/ / /_/ /| |/ |/ / /_/ / / / /
\____/\__/_/ /_____/\__, / |__/|__/\____/_/ /_/
                   /____/
    QUIC Initial Packet Fuzzer (RFC 9000 / RFC 9001)
    OffByWon Framework v2.0
"""


# =============================================================================
# QUIC PROTOCOL CONSTANTS
# =============================================================================

# Initial salts (RFC 9001 5.2 for v1, RFC 9369 for v2)
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

QUIC_VERSION_1 = 0x00000001
QUIC_VERSION_2 = 0x6b3343cf  # RFC 9369

# QUIC frame type codes (RFC 9000 12.4)
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_CRYPTO = 0x06
FRAME_CONNECTION_CLOSE = 0x1c

# TLS / handshake
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_AES_128_GCM_SHA256 = 0x1301


# =============================================================================
# QUIC INITIAL CRYPTO LAYER (RFC 9001)
# =============================================================================

class QUICInitialCrypto:
    """
    Computes RFC 9001 Initial keys from a Destination Connection ID and applies
    AEAD packet protection + AES-ECB header protection.

    Validated against RFC 9001 Appendix A.2 (see self_test()).
    """

    def __init__(self, dcid: bytes, version: int = QUIC_VERSION_1):
        self.version = version
        if version == QUIC_VERSION_2:
            salt = INITIAL_SALT_V2
            self.l_key, self.l_iv, self.l_hp = b"quicv2 key", b"quicv2 iv", b"quicv2 hp"
        else:
            salt = INITIAL_SALT_V1
            self.l_key, self.l_iv, self.l_hp = b"quic key", b"quic iv", b"quic hp"

        initial_secret = self._hkdf_extract(salt, dcid)
        # We send as the client, so we protect with the client keys.
        self.client_secret = self._hkdf_expand_label(initial_secret, b"client in", 32)
        self.server_secret = self._hkdf_expand_label(initial_secret, b"server in", 32)

        self.key = self._hkdf_expand_label(self.client_secret, self.l_key, 16)
        self.iv = self._hkdf_expand_label(self.client_secret, self.l_iv, 12)
        self.hp = self._hkdf_expand_label(self.client_secret, self.l_hp, 16)

        # Server keys (to decrypt responses for liveness verification)
        self.s_key = self._hkdf_expand_label(self.server_secret, self.l_key, 16)
        self.s_iv = self._hkdf_expand_label(self.server_secret, self.l_iv, 12)
        self.s_hp = self._hkdf_expand_label(self.server_secret, self.l_hp, 16)

    # -- HKDF (RFC 5869 + TLS 1.3 HKDF-Expand-Label) --------------------------

    @staticmethod
    def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
        h = HMAC(salt, SHA256())
        h.update(ikm)
        return h.finalize()

    @staticmethod
    def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
        full_label = b"tls13 " + label
        info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
        return HKDFExpand(algorithm=SHA256(), length=length, info=info).derive(secret)

    # -- Packet protection ----------------------------------------------------

    def protect(self, header: bytes, payload: bytes, pn: int, pn_len: int) -> bytes:
        """
        Apply AEAD protection and header protection to a long-header Initial.

        Args:
            header: cleartext header bytes, ending with the (unprotected) packet
                    number field of length pn_len.
            payload: the (already assembled) frame bytes to encrypt.
            pn: the full packet number value used for the nonce.
            pn_len: number of bytes the packet number occupies in the header.

        Returns:
            The fully protected datagram bytes.
        """
        # AEAD nonce = packet number left-padded to the 12-byte IV, XOR iv
        # (RFC 9001 5.3). pn_full(8) padded with 4 leading zero bytes == 12.
        pn_full = pn.to_bytes(8, "big")
        padded_pn = b"\x00\x00\x00\x00" + pn_full
        nonce = bytes(a ^ b for a, b in zip(self.iv, padded_pn))
        ciphertext = AESGCM(self.key).encrypt(nonce, payload, header)

        packet = bytearray(header + ciphertext)
        pn_offset = len(header) - pn_len

        # Header protection (RFC 9001 5.4): sample 16 bytes starting 4 bytes
        # into the packet number field (treating PN as if it were 4 bytes).
        sample_offset = pn_offset + 4
        sample = bytes(packet[sample_offset:sample_offset + 16])
        enc = Cipher(algorithms.AES(self.hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()

        # Long header: mask the low 4 bits of the first byte.
        packet[0] ^= mask[0] & 0x0f
        for i in range(pn_len):
            packet[pn_offset + i] ^= mask[1 + i]

        return bytes(packet)

    def remove_header_protection_server(self, datagram: bytes) -> Optional[Tuple[int, int, bytes]]:
        """
        Best-effort removal of header protection on a server long header, used
        only to confirm a response decrypts (liveness). Returns (pn, pn_len,
        first_byte) or None. Parsing failures are non-fatal.
        """
        try:
            if not datagram or not (datagram[0] & 0x80):
                return None
            # Skip: first(1) ver(4) dcidlen(1) dcid scidlen(1) scid token(varint) len(varint)
            off = 1 + 4
            dl = datagram[off]; off += 1 + dl
            sl = datagram[off]; off += 1 + sl
            # token length (server Initial has none, but parse defensively)
            tl, n = self._read_varint(datagram, off); off += n + tl
            _, n = self._read_varint(datagram, off); off += n  # length field
            pn_offset = off
            sample = datagram[pn_offset + 4:pn_offset + 4 + 16]
            enc = Cipher(algorithms.AES(self.s_hp), modes.ECB()).encryptor()
            mask = enc.update(sample) + enc.finalize()
            first = datagram[0] ^ (mask[0] & 0x0f)
            pn_len = (first & 0x03) + 1
            pn = 0
            for i in range(pn_len):
                pn = (pn << 8) | (datagram[pn_offset + i] ^ mask[1 + i])
            return pn, pn_len, first
        except Exception:
            return None

    @staticmethod
    def _read_varint(buf: bytes, off: int) -> Tuple[int, int]:
        first = buf[off]
        prefix = first >> 6
        length = 1 << prefix
        val = first & 0x3f
        for i in range(1, length):
            val = (val << 8) | buf[off + i]
        return val, length


def encode_varint(value: int) -> bytes:
    """Standalone QUIC varint encoder (RFC 9000 16) for manual assembly."""
    if value <= 63:
        return bytes([value])
    if value <= 16383:
        return struct.pack(">H", 0x4000 | value)
    if value <= 1073741823:
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


# =============================================================================
# OFFBYWON PACKET DEFINITIONS
# =============================================================================
#
# Every QUIC/TLS structure below is described declaratively with the OffByWon
# Field API. VARINT is the framework's native QUIC variable-length integer;
# LENGTH/size_type=WORD_BE produces the big-endian 2-byte length prefixes TLS
# uses. QUIC varint lengths remain explicit VARINT fields because automatic
# LENGTH fixups require a fixed-width size_type.
# =============================================================================

class QUICInitialHeaderTpl(Packet):
    """
    Cleartext QUIC v1 Initial long header (RFC 9000 17.2.2), used as a fuzzing
    template for the fields a server parses BEFORE decryption.

    Note: this template is for *structured field fuzzing of the header*. For
    correctly-encrypted packets the header is assembled by build_header() so the
    AEAD AAD and length varint stay self-consistent. The two share field names.
    """
    fields = [
        # First byte: 1100 0011 = long(1) fixed(1) Initial(00) reserved(00) PNlen(11=4)
        Field('first_byte', FieldType.BYTE, 0xC3),
        Field('version', FieldType.DWORD_BE, QUIC_VERSION_1, fuzz=True),
        Field('dcid_len', FieldType.BYTE, 8),
        Field('dcid', FieldType.BYTES),
        Field('scid_len', FieldType.BYTE, 8),
        Field('scid', FieldType.BYTES),
        Field('token_len', FieldType.VARINT, 0),
        Field('token', FieldType.BYTES),
        # length covers packet number + protected payload (varint, RFC 9000)
        Field('length', FieldType.VARINT, 0),
        Field('packet_number', FieldType.DWORD_BE, 0),
    ]


class CryptoFrameTpl(Packet):
    """
    QUIC CRYPTO frame (RFC 9000 19.6): type(varint)=0x06, offset(varint),
    length(varint), crypto data. The offset/length varints are prime targets:
    they drive quinn's crypto-stream reassembly buffer math.

    NOTE: 'length' is a plain VARINT set explicitly to len(data) by the caller,
    NOT a FieldType.LENGTH auto-resolver. Automatic LENGTH fields reject a
    VARINT size_type because a variable-width placeholder cannot be fixed up
    in place. A native VARINT field
    encodes correctly AND is the right fuzzing surface: get_fuzz_integer(VARINT)
    draws from VARINT_BOUNDARIES, so a length/field-mode mutation here produces
    a valid-width varint that legitimately disagrees with the data that follows.
    """
    fields = [
        Field('frame_type', FieldType.VARINT, FRAME_CRYPTO, fuzz=False),
        Field('offset', FieldType.VARINT, 0),
        Field('length', FieldType.VARINT, 0),
        Field('data', FieldType.BYTES, fuzz=False),
    ]


class TLSExtensionTpl(Packet):
    """Generic TLS extension: type(2) + length(2, big-endian) + data."""
    fields = [
        Field('ext_type', FieldType.WORD_BE, 0),
        Field('ext_len', FieldType.LENGTH, target='ext_data', size_type=FieldType.WORD_BE),
        Field('ext_data', FieldType.BYTES),
    ]


class ClientHelloBodyTpl(Packet):
    """
    TLS 1.3 ClientHello body (RFC 8446 4.1.2), minus the 1+3 handshake header
    which is prepended manually (TLS uses a 24-bit length that the framework's
    integer types do not model directly).

    All TLS vectors here are 1- or 2-byte length-prefixed, which the framework
    expresses with BYTE / LENGTH(size_type=WORD_BE).
    """
    fields = [
        Field('legacy_version', FieldType.WORD_BE, 0x0303),
        Field('random', FieldType.BYTES, size=32),
        Field('session_id_len', FieldType.LENGTH, target='session_id', size_type=FieldType.BYTE),
        Field('session_id', FieldType.BYTES),
        Field('cipher_suites_len', FieldType.LENGTH, target='cipher_suites', size_type=FieldType.WORD_BE),
        Field('cipher_suites', FieldType.BYTES),
        Field('compression_len', FieldType.LENGTH, target='compression', size_type=FieldType.BYTE),
        Field('compression', FieldType.BYTES),
        Field('extensions_len', FieldType.LENGTH, target='extensions', size_type=FieldType.WORD_BE),
        Field('extensions', FieldType.BYTES),
    ]


# =============================================================================
# QUIC INITIAL FUZZER
# =============================================================================

class QUICInitialFuzzer:
    """
    QUIC Initial packet fuzzer using the OffByWon framework.

    Multi-layer structured fuzzing of the cleartext header, the encrypted QUIC
    frame layer, the TLS ClientHello, and QUIC transport parameters, with
    correct RFC 9001 packet protection so mutations reach the real parsers.
    """

    def __init__(self):
        self.fw = Framework(verbose=False, color=True)

        # Connection
        self.host: str = None
        self.port: int = 4433
        self.sock: socket.socket = None
        self.timeout: float = 1.0        # liveness/baseline wait
        self.send_timeout: float = 0.25  # per-fuzz-packet drain (most are dropped)
        self.family = socket.AF_INET

        # QUIC parameters
        self.version: int = QUIC_VERSION_1
        self.alpn: bytes = b"hq-29"
        self.server_name: str = "localhost"

        # Fuzzing settings
        self.fuzzing: bool = False
        self.fuzz_targets: List[str] = ['all']
        self.fuzz_mode: str = 'field'
        self.fuzz_count: Optional[int] = None
        self.byteflip_count: int = 1
        self.blind_mode: bool = False
        self.combined_mode: bool = False
        self.byteflip_mode: bool = False
        self.fuzz_len_mode: bool = False
        self.dry_run: bool = False
        self.verbose: bool = False
        self.quiet: bool = False
        self.iterations: Optional[int] = None
        self.liveness_every: int = 200
        self.print_every: int = 2000
        self.no_padding: bool = False

        # Statistics
        self.packet_count: int = 0
        self.crash_count: int = 0
        self.response_count: int = 0
        self.consecutive_dead: int = 0
        self._start_time: float = 0.0
        self._last_status: float = 0.0
        self._target_counts: Dict[str, int] = {}
        self._status_active: bool = False  # a \r status line is currently on screen

        # Output tracking (OffByWon standardized format)
        self._current_mutations: List[Tuple[str, Any, Any, str]] = []
        self._current_byteflips: List[Tuple[int, int, int]] = []
        self._current_note: str = ""

    # =========================================================================
    # AVAILABLE FUZZ TARGETS
    # =========================================================================

    @staticmethod
    def get_available_targets() -> List[str]:
        return [
            "header",            # cleartext long header (pre-decryption parse)
            "crypto_frame",      # CRYPTO frame offset/length varints
            "frames",            # frame-type varint + injected frames
            "tls",               # TLS ClientHello length vectors
            "transport_params",  # QUIC transport parameters extension
        ]

    # =========================================================================
    # OFFBYWON OUTPUT FORMAT
    # =========================================================================

    def _print_packet_output(self, packet_name: str, mode: str, data: bytes):
        CYAN = '\033[96m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
        BOLD = '\033[1m'; RESET = '\033[0m'; DIM = '\033[2m'

        print()
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}[OffByWon]{RESET} {BOLD}PACKET #{self.packet_count}{RESET}")
        print(f"Type: {YELLOW}{packet_name}{RESET} | Mode: {GREEN}{mode}{RESET}")
        if self._current_note:
            print(f"Layer: {DIM}{self._current_note}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")

        if self._current_mutations:
            print(f"{BOLD}Structured mutations:{RESET}")
            for field, orig, fuzzed, strategy in self._current_mutations:
                print(f"  {GREEN}->{RESET} {field}: {DIM}{self._format_value(orig)}{RESET}"
                      f" -> {YELLOW}{self._format_value(fuzzed)}{RESET} ({strategy})")

        if self._current_byteflips:
            print(f"{BOLD}Byteflips:{RESET} {len(self._current_byteflips)}")
            for offset, orig, fuzzed in self._current_byteflips[:5]:
                print(f"  {GREEN}->{RESET} offset {offset}: {DIM}0x{orig:02x}{RESET} -> {YELLOW}0x{fuzzed:02x}{RESET}")
            if len(self._current_byteflips) > 5:
                print(f"  {DIM}-> ... and {len(self._current_byteflips) - 5} more{RESET}")

        if not self._current_mutations and not self._current_byteflips:
            print(f"{DIM}Mutations: none (clean packet){RESET}")

        print(f"{CYAN}{'='*70}{RESET}")
        print(f"Size: {len(data)} bytes")
        hex_str = data.hex()
        if len(hex_str) > 100:
            hex_str = hex_str[:100] + f'{DIM}...{RESET}'
        print(f"Hex: {DIM}{hex_str}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")

    def _format_value(self, value: Any) -> str:
        if isinstance(value, bytes):
            return value.hex() if len(value) <= 16 else f"({len(value)} bytes)"
        if isinstance(value, int):
            if value > 0xFFFF:
                return f"0x{value:x}"
            if value > 255:
                return f"{value} (0x{value:x})"
            return str(value)
        if isinstance(value, str):
            return f'"{value[:20]}..."' if len(value) > 20 else f'"{value}"'
        return str(value)

    def _add_mutation(self, field: str, original: Any, fuzzed: Any, strategy: str):
        self._current_mutations.append((field, original, fuzzed, strategy))

    def _remaining_fuzz_count(self) -> Optional[int]:
        """Return the remaining structured-field mutation budget."""
        if self.fuzz_count is None:
            return None
        return max(0, self.fuzz_count - len(self._current_mutations))

    def _can_fuzz_structured(self) -> bool:
        remaining = self._remaining_fuzz_count()
        return remaining is None or remaining > 0

    def _reset_mutations(self):
        self._current_mutations = []
        self._current_byteflips = []
        self._current_note = ""

    def log(self, message: str, level: str = "VERBOSE"):
        if level == "ALWAYS" or (level == "VERBOSE" and self.verbose):
            print(message)

    def _clear_status(self):
        """Erase the in-place live status line before printing a full block."""
        if self._status_active:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            self._status_active = False

    def _status_line(self, target: str, last_resp: int, force: bool = False):
        """
        Live, in-place progress line (carriage-return updated) so a long run is
        never a black box. Throttled to ~5 Hz. Shows rate, counts, current
        target and a compact spread of which targets have been exercised.
        """
        if self.quiet or self.verbose:
            return
        now = time.monotonic()
        if not force and (now - self._last_status) < 0.2:
            return
        self._last_status = now
        elapsed = max(1e-6, now - self._start_time)
        rate = self.packet_count / elapsed
        spread = " ".join(f"{t[:4]}={self._target_counts.get(t, 0)}"
                          for t in self.get_available_targets())
        GREEN = '\033[92m'; CYAN = '\033[96m'; YELLOW = '\033[93m'; RESET = '\033[0m'
        line = (f"\r{CYAN}[fuzz]{RESET} #{self.packet_count} "
                f"{GREEN}{rate:6.0f}/s{RESET} "
                f"resp={self.response_count} crash={self.crash_count} "
                f"now={YELLOW}{target or 'clean'}{RESET} | {spread}")
        sys.stdout.write(line + "\033[K")
        sys.stdout.flush()
        self._status_active = True

    # =========================================================================
    # TLS CLIENTHELLO CONSTRUCTION (via OffByWon)
    # =========================================================================

    def build_transport_parameters(self, scid: bytes, fuzz: bool = False) -> bytes:
        """
        Build the QUIC transport parameters extension payload (RFC 9000 18).
        Each parameter is id(varint) + length(varint) + value. We use OffByWon
        to encode the varints and (optionally) fuzz the lengths.
        """
        def tp(param_id: int, value: bytes) -> bytes:
            return encode_varint(param_id) + encode_varint(len(value)) + value

        # NB: do NOT send 0x00 (original_destination_connection_id), 0x02
        # (stateless_reset_token), 0x10 (retry_source_connection_id) or 0x0d
        # (preferred_address) - those are server-only and a client sending them
        # is a mandatory TRANSPORT_PARAMETER_ERROR (RFC 9000 18.2).
        params = b""
        params += tp(0x0f, scid)                       # initial_source_connection_id MUST equal our SCID
        params += tp(0x01, encode_varint(30000))       # max_idle_timeout
        params += tp(0x04, encode_varint(1048576))     # initial_max_data
        params += tp(0x05, encode_varint(262144))      # initial_max_stream_data_bidi_local
        params += tp(0x06, encode_varint(262144))      # initial_max_stream_data_bidi_remote
        params += tp(0x07, encode_varint(262144))      # initial_max_stream_data_uni
        params += tp(0x08, encode_varint(100))         # initial_max_streams_bidi
        params += tp(0x09, encode_varint(100))         # initial_max_streams_uni
        params += tp(0x03, encode_varint(65527))       # max_udp_payload_size

        if fuzz and self._can_fuzz_structured():
            # Off-by-one / boundary fuzzing of a transport parameter LENGTH varint:
            # claim a length that disagrees with the value bytes that follow.
            strat = random.choice(['len_overflow', 'len_underflow', 'huge_id', 'huge_varint_value'])
            if strat == 'len_overflow':
                bad = encode_varint(0x0f) + encode_varint(64) + scid  # says 64, has len(scid)
                params = bad + params
                self._add_mutation('tp[0x0f].length', len(scid), 64, 'length_mismatch_long')
            elif strat == 'len_underflow':
                bad = encode_varint(0x04) + encode_varint(0) + encode_varint(1048576)
                params = bad + params
                self._add_mutation('tp[0x04].length', 4, 0, 'length_mismatch_short')
            elif strat == 'huge_id':
                pid = random.choice(VARINT_BOUNDARIES)
                params = encode_varint(pid) + encode_varint(4) + b'\x00\x00\x00\x00' + params
                self._add_mutation('tp.id', '(known)', pid, 'boundary')
            else:
                val, s = get_fuzz_integer(FieldType.VARINT, 1048576)
                params = encode_varint(0x04) + encode_varint(8) + encode_varint(val) + params
                self._add_mutation('tp[0x04].value', 1048576, val, s)

        return params

    def build_client_hello(self, scid: bytes, fuzz_tls: bool = False,
                           fuzz_tp: bool = False) -> bytes:
        """
        Build a TLS 1.3 ClientHello carrying QUIC transport parameters, wrapped
        as a handshake message. Uses OffByWon for the ClientHello body and each
        extension; the 24-bit handshake length is prepended manually.
        """
        # --- x25519 key share (real key so the server can attempt ECDH) ------
        priv = X25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        def ext(ext_type: int, data: bytes, fuzz=False) -> bytes:
            fuzz = fuzz and self._can_fuzz_structured()
            d, info = self.fw.build(
                TLSExtensionTpl,
                mode=('length' if fuzz else 'clean'),
                values={'ext_type': ext_type, 'ext_data': data},
                fields=['ext_len'] if fuzz else None,
                fuzz_count=self._remaining_fuzz_count() if fuzz else None,
            )
            for mutation in info.mutations:
                self._add_mutation(
                    f'TLS.ext[0x{ext_type:04x}].{mutation.field}',
                    mutation.original,
                    mutation.fuzzed,
                    mutation.strategy,
                )
            return d

        # supported_versions: TLS 1.3
        e_versions = ext(0x002b, bytes([2]) + struct.pack(">H", 0x0304))
        # supported_groups: x25519
        e_groups = ext(0x000a, struct.pack(">H", 2) + struct.pack(">H", 0x001d))
        # key_share: x25519 pubkey
        ks_entry = struct.pack(">H", 0x001d) + struct.pack(">H", len(pub)) + pub
        e_keyshare = ext(0x0033, struct.pack(">H", len(ks_entry)) + ks_entry)
        # signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519
        sigalgs = struct.pack(">HHH", 0x0403, 0x0804, 0x0807)
        e_sigalgs = ext(0x000d, struct.pack(">H", len(sigalgs)) + sigalgs)
        # ALPN
        alpn_list = bytes([len(self.alpn)]) + self.alpn
        e_alpn = ext(0x0010, struct.pack(">H", len(alpn_list)) + alpn_list)
        # SNI
        sni = self.server_name.encode()
        sni_entry = bytes([0]) + struct.pack(">H", len(sni)) + sni
        e_sni = ext(0x0000, struct.pack(">H", len(sni_entry)) + sni_entry)
        # QUIC transport parameters (ext 0x0039)
        tp = self.build_transport_parameters(scid, fuzz=fuzz_tp)
        e_tp = ext(0x0039, tp, fuzz=fuzz_tls and random.random() < 0.5)

        extensions = (e_sni + e_alpn + e_groups + e_sigalgs +
                      e_versions + e_keyshare + e_tp)

        # Optionally fuzz one ClientHello-body length vector (reaches rustls).
        ch_fuzz_fields = None
        ch_mode = 'clean'
        if fuzz_tls and self._can_fuzz_structured():
            ch_mode = 'length'
            ch_fuzz_fields = [random.choice(
                ['session_id_len', 'cipher_suites_len', 'compression_len', 'extensions_len'])]

        body, info = self.fw.build(
            ClientHelloBodyTpl,
            mode=ch_mode,
            values={
                'random': os.urandom(32),
                'session_id': os.urandom(32),  # TLS 1.3 compat: 32-byte session id
                'cipher_suites': struct.pack(">H", TLS_AES_128_GCM_SHA256),
                'compression': b'\x00',
                'extensions': extensions,
            },
            fields=ch_fuzz_fields,
            fuzz_count=self._remaining_fuzz_count() if ch_fuzz_fields else None,
        )
        for mutation in info.mutations:
            self._add_mutation(
                f'ClientHello.{mutation.field}', mutation.original,
                mutation.fuzzed, mutation.strategy,
            )

        # Handshake header: msg_type(1) + length(3, big-endian)
        handshake = bytes([TLS_HANDSHAKE_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
        return handshake

    # =========================================================================
    # QUIC INITIAL PACKET CONSTRUCTION
    # =========================================================================

    def build_header(self, dcid: bytes, scid: bytes, token: bytes,
                     payload_len: int, pn: int, pn_len: int,
                     first_byte: int = 0xC3, version: int = None) -> bytes:
        """
        Assemble the cleartext long header with a self-consistent length varint.
        Used for correctly-encrypted packets.
        """
        version = version if version is not None else self.version
        length_field = pn_len + payload_len + 16  # PN + payload + 16-byte AEAD tag
        return (
            bytes([first_byte]) +
            struct.pack(">I", version) +
            bytes([len(dcid)]) + dcid +
            bytes([len(scid)]) + scid +
            encode_varint(len(token)) + token +
            encode_varint(length_field) +
            pn.to_bytes(pn_len, "big")
        )

    def build_initial_payload(self, scid: bytes, fuzz_target: str = None,
                              mode: str = 'clean') -> bytes:
        """
        Build the QUIC Initial payload (frame layer): a CRYPTO frame carrying the
        ClientHello, optionally fuzzed, plus extra frames. Padding to the 1200-
        byte datagram minimum is added by the caller after encryption sizing.
        """
        fuzz_tls = fuzz_target in ('tls', 'all')
        fuzz_tp = fuzz_target in ('transport_params', 'all')
        client_hello = self.build_client_hello(scid, fuzz_tls=fuzz_tls, fuzz_tp=fuzz_tp)

        # --- CRYPTO frame via OffByWon ---------------------------------------
        crypto_mode = 'clean'
        crypto_fields = None
        if fuzz_target in ('crypto_frame', 'all') and self._can_fuzz_structured():
            # Raw byteflips are applied once to the final protected datagram,
            # never inside the plaintext CRYPTO frame.
            crypto_mode = 'length' if mode == 'length' else 'field'
            crypto_fields = ['offset', 'length']
            remaining = self._remaining_fuzz_count()
            if remaining is not None and remaining < len(crypto_fields):
                crypto_fields = random.sample(crypto_fields, remaining)

        crypto_frame, info = self.fw.build(
            CryptoFrameTpl,
            mode=crypto_mode,
            values={'frame_type': FRAME_CRYPTO, 'offset': 0,
                    'length': len(client_hello), 'data': client_hello},
            fields=crypto_fields,
            fuzz_count=self._remaining_fuzz_count() if crypto_fields else None,
        )
        for m in info.mutations:
            self._add_mutation(f'CRYPTO.{m.field}', m.original, m.fuzzed, m.strategy)

        frames = crypto_frame

        # --- Frame-layer fuzzing: inject / mutate extra frames ---------------
        if fuzz_target in ('frames', 'all') and self._can_fuzz_structured():
            strat = random.choice(['unknown_frame_type', 'ping', 'huge_offset_crypto',
                                    'duplicate_crypto', 'malformed_ack'])
            if strat == 'unknown_frame_type':
                ftype = random.choice(VARINT_BOUNDARIES + [0x1f, 0x20, 0x3f, 0xff])
                frames = encode_varint(ftype) + frames
                self._add_mutation('frame.type', '(crypto)', ftype, 'unknown_frame_type')
            elif strat == 'ping':
                frames = bytes([FRAME_PING]) + frames
                self._add_mutation('frame', '(none)', 'PING', 'inject')
            elif strat == 'huge_offset_crypto':
                off = random.choice([v for v in VARINT_BOUNDARIES if v > 1000])
                extra, _ = self.fw.build(CryptoFrameTpl, mode='clean',
                                         values={'offset': off, 'length': 16,
                                                 'data': os.urandom(16)})
                frames = frames + extra
                self._add_mutation('CRYPTO.offset(2nd)', 0, off, 'boundary')
            elif strat == 'duplicate_crypto':
                frames = frames + crypto_frame  # overlapping crypto offsets
                self._add_mutation('CRYPTO', '(1x)', '(2x overlap)', 'duplicate')
            else:  # malformed_ack: largest_acked huge, then bad range count
                ack = (bytes([FRAME_ACK]) + encode_varint(random.choice(VARINT_BOUNDARIES)) +
                       encode_varint(0) + encode_varint(random.choice(COUNT_VALUES)) +
                       encode_varint(random.choice(VARINT_BOUNDARIES)))
                frames = ack + frames
                self._add_mutation('ACK', '(none)', 'malformed range', 'inject')

        return frames

    def build_packet(self, fuzz_target: str = None, mode: str = 'clean') -> bytes:
        """
        Build a complete, protected (or header-fuzzed) QUIC Initial datagram.

        Returns the bytes to send on the wire.
        """
        self._reset_mutations()

        dcid = os.urandom(8)
        scid = os.urandom(8)
        crypto = QUICInitialCrypto(dcid, self.version)
        self._last_crypto = crypto  # exposed so probes can decrypt the response
        pn = random.randint(0, 3)
        pn_len = 4

        structured_mode = mode in ('field', 'length', 'combined', 'full')
        structured_target = fuzz_target if structured_mode and self._can_fuzz_structured() else None

        # -------- Header-layer fuzzing (parsed before decryption) ------------
        if structured_target == 'header':
            packet = self._build_header_fuzzed(crypto, dcid, scid, pn, pn_len, mode)
        else:
            # ------ Payload / frame / TLS / TP fuzzing (re-encrypted) --------
            self._current_note = f"encrypted; fuzzing '{structured_target or 'none'}'"
            payload = self.build_initial_payload(
                scid, fuzz_target=structured_target, mode=mode,
            )

            # Pad payload so the datagram reaches the 1200-byte client minimum
            # (RFC 9000 14.1). Padding frames are 0x00 bytes.
            header_len_est = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 1 + 4
            min_payload = 1200 - header_len_est - 16
            if not self.no_padding and len(payload) < min_payload:
                payload = payload + b'\x00' * (min_payload - len(payload))

            header = self.build_header(dcid, scid, b'', len(payload), pn, pn_len)
            packet = crypto.protect(header, payload, pn, pn_len)

        # Optional byteflip / combined / blind post-encryption corruption,
        # delegated to the framework helpers (tests the AEAD gate + transport).
        if mode in ('byteflip', 'combined', 'full'):
            packet, flips = self.fw._apply_byteflips(packet, self.byteflip_count)
            self._current_byteflips = [(f.offset, f.original, f.fuzzed) for f in flips]
        if mode in ('blind', 'full'):
            packet, mutation = self.fw._apply_blind_corruption(
                packet, return_mutation=True,
            )
            self._add_mutation(
                mutation.field, mutation.original, mutation.fuzzed,
                mutation.strategy,
            )

        return packet

    def _build_header_fuzzed(self, crypto: QUICInitialCrypto, dcid: bytes,
                             scid: bytes, pn: int, pn_len: int, mode: str) -> bytes:
        """
        Fuzz the cleartext long header. The header is parsed by the server before
        any decryption, so these mutations are reachable even though they will
        usually break AEAD. We still encrypt a real payload underneath so the
        datagram is well-formed up to the point under test.
        """
        self._current_note = "cleartext long header (pre-decryption parse target)"
        client_hello = self.build_client_hello(scid)
        crypto_frame, _ = self.fw.build(
            CryptoFrameTpl, mode='clean',
            values={'offset': 0, 'length': len(client_hello), 'data': client_hello})
        header_len_est = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 1 + 4
        min_payload = 1200 - header_len_est - 16
        payload = crypto_frame
        if len(payload) < min_payload:
            payload += b'\x00' * (min_payload - len(payload))

        # Pick a header field to corrupt and a strategy.
        fuzz_field = random.choice(
            ['version', 'dcid_len', 'scid_len', 'token_len', 'length', 'first_byte', 'reserved_bits'])

        first_byte = 0xC3
        token = b''
        version = self.version
        real_length = pn_len + len(payload) + 16
        length_field = real_length
        dcid_decl = bytes([len(dcid)])
        scid_decl = bytes([len(scid)])

        if fuzz_field == 'version':
            version, s = get_fuzz_integer(FieldType.DWORD_BE, self.version)
            self._add_mutation('version', f'0x{self.version:08x}', f'0x{version:08x}', s)
        elif fuzz_field == 'dcid_len':
            bad = random.choice([0, 1, 19, 20, 21, 255] + list(range(2, 8)))
            dcid_decl = bytes([bad])  # declared length disagrees with actual DCID bytes
            self._add_mutation('dcid_len', len(dcid), bad, 'length_mismatch')
        elif fuzz_field == 'scid_len':
            bad = random.choice([0, 1, 19, 20, 21, 255])
            scid_decl = bytes([bad])
            self._add_mutation('scid_len', len(scid), bad, 'length_mismatch')
        elif fuzz_field == 'token_len':
            tlv = random.choice(VARINT_BOUNDARIES)
            token = b''  # claim a token length with no token bytes following
            self._current_note += f"; token_len={tlv} with empty token"
            self._add_mutation('token_len', 0, tlv, 'length_mismatch')
            # Assemble manually to inject the bogus token length varint.
            header = (bytes([first_byte]) + struct.pack(">I", version) +
                      dcid_decl + dcid + scid_decl + scid +
                      encode_varint(tlv) + token +
                      encode_varint(length_field) + pn.to_bytes(pn_len, "big"))
            return crypto.protect(header, payload, pn, pn_len)
        elif fuzz_field == 'length':
            delta = random.choice(LENGTH_DELTAS)
            length_field = max(0, real_length + delta)
            self._add_mutation('length', real_length, f'{length_field} (delta {delta:+d})',
                               'length_mismatch')
        elif fuzz_field == 'first_byte':
            first_byte, s = get_fuzz_integer(FieldType.BYTE, 0xC3)
            self._add_mutation('first_byte', '0xc3', f'0x{first_byte:02x}', s)
        elif fuzz_field == 'reserved_bits':
            first_byte = 0xC3 | 0x0C  # set the two reserved bits (MUST be 0 -> error)
            self._add_mutation('first_byte.reserved', '0b00', '0b11', 'reserved_bits_set')

        header = (bytes([first_byte]) + struct.pack(">I", version) +
                  dcid_decl + dcid + scid_decl + scid +
                  encode_varint(len(token)) + token +
                  encode_varint(length_field) + pn.to_bytes(pn_len, "big"))
        return crypto.protect(header, payload, pn, pn_len)

    # =========================================================================
    # NETWORK
    # =========================================================================

    def _resolve_family(self):
        try:
            socket.inet_pton(socket.AF_INET6, self.host)
            self.family = socket.AF_INET6
        except OSError:
            self.family = socket.AF_INET

    def connect(self):
        self._resolve_family()
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.settimeout(self.send_timeout)

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_and_recv(self, data: bytes, timeout: float = None) -> Optional[bytes]:
        """
        Send one datagram and wait up to `timeout` for a response. Used for the
        baseline and liveness probes, where we genuinely want to block for a
        reply. ConnectionRefusedError (ICMP port-unreachable) propagates.
        """
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            self.sock.sendto(data, (self.host, self.port))
        except OSError as e:
            self.log(f"[!] send error: {e}", "VERBOSE")
            return None
        try:
            resp, _ = self.sock.recvfrom(65535)
            return resp
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            raise
        except OSError as e:
            self.log(f"[!] recv error: {e}", "VERBOSE")
            return None

    def fuzz_send(self, data: bytes) -> int:
        """
        High-throughput fuzz send: fire the datagram and non-blocking-drain any
        responses already queued (replies to this or recent packets pipeline in).
        We do NOT block waiting for a reply - most fuzzed packets are silently
        dropped by the server, so blocking would throttle the fuzzer. Crash
        detection is handled by the periodic liveness probe instead.

        Returns the number of response datagrams drained. Raises
        ConnectionRefusedError if the OS reports the port is unreachable.
        """
        self.sock.sendto(data, (self.host, self.port))  # may raise ConnectionRefusedError
        drained = 0
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    self.sock.recvfrom(65535)
                    drained += 1
                except BlockingIOError:
                    break
                except ConnectionRefusedError:
                    raise
                except OSError:
                    break
        finally:
            self.sock.setblocking(True)
            self.sock.settimeout(self.send_timeout)
        return drained

    def classify_server_initial(self, datagram: bytes, crypto: 'QUICInitialCrypto') -> str:
        """
        Decrypt a server Initial response and classify it by the frames it
        carries. This is the real correctness check: a progressing handshake
        contains CRYPTO (ServerHello) / ACK; a rejected packet contains
        CONNECTION_CLOSE (0x1c/0x1d). "Got a datagram back" alone is NOT success.

        Returns: 'handshake' | 'close:<errcode>' | 'unknown' | 'undecryptable'.
        """
        try:
            if not datagram or not (datagram[0] & 0x80):
                return 'unknown'  # not a long header (e.g. coalesced/short)
            off = 1 + 4
            dl = datagram[off]; off += 1 + dl
            sl = datagram[off]; off += 1 + sl
            tl, n = crypto._read_varint(datagram, off); off += n + tl
            length, n = crypto._read_varint(datagram, off); off += n
            pn_off = off
            sample = datagram[pn_off + 4:pn_off + 4 + 16]
            enc = Cipher(algorithms.AES(crypto.s_hp), modes.ECB()).encryptor()
            mask = enc.update(sample) + enc.finalize()
            first = datagram[0] ^ (mask[0] & 0x0f)
            pn_len = (first & 0x03) + 1
            pnb = bytes(datagram[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
            pn = int.from_bytes(pnb, 'big')
            hdr = bytearray(datagram[:pn_off + pn_len])
            hdr[0] = first
            for i in range(pn_len):
                hdr[pn_off + i] = pnb[i]
            ct = datagram[pn_off + pn_len: pn_off + (length - pn_len) + pn_len]
            ct = datagram[pn_off + pn_len: pn_off + length]  # length covers pn+payload+tag
            nonce = bytes(a ^ b for a, b in zip(crypto.s_iv, b'\x00' * 4 + pn.to_bytes(8, 'big')))
            plain = AESGCM(crypto.s_key).decrypt(nonce, ct, bytes(hdr))
            # Scan the Initial payload's frames. A server Initial typically
            # carries ACK (acknowledging our packet) followed by CRYPTO
            # (ServerHello); a rejection carries CONNECTION_CLOSE.
            rv = crypto._read_varint
            i = 0
            saw_crypto = False
            while i < len(plain):
                ft, ln = rv(plain, i); i += ln
                if ft in (0x00, 0x01):           # PADDING / PING
                    continue
                if ft in (0x1c, 0x1d):           # CONNECTION_CLOSE
                    errcode, _ = rv(plain, i)
                    return f'close:0x{errcode:x}'
                if ft == 0x06:                   # CRYPTO
                    _, oln = rv(plain, i); i += oln
                    clen, cln = rv(plain, i); i += cln
                    i += clen
                    saw_crypto = True
                    continue
                if ft in (0x02, 0x03):           # ACK / ACK_ECN
                    _, l1 = rv(plain, i); i += l1          # largest acked
                    _, l2 = rv(plain, i); i += l2          # ack delay
                    rc, l3 = rv(plain, i); i += l3         # range count
                    _, l4 = rv(plain, i); i += l4          # first ack range
                    for _ in range(rc):
                        _, lg = rv(plain, i); i += lg       # gap
                        _, lr = rv(plain, i); i += lr       # range length
                    if ft == 0x03:
                        for _ in range(3):                  # ECT0/ECT1/ECN-CE
                            _, le = rv(plain, i); i += le
                    continue
                break                            # unknown frame type -> stop
            return 'handshake' if saw_crypto else 'unknown'
        except Exception:
            return 'undecryptable'

    def is_alive(self) -> bool:
        """
        Liveness probe: send a clean, valid Initial and require a response.
        A live quinn server answers a valid Initial with its own Initial
        (ServerHello or a CONNECTION_CLOSE), proving the process is up.
        """
        # The probe must be a fully valid Initial regardless of fuzzing flags:
        # quinn (correctly) drops client Initials < 1200 bytes without replying,
        # so --no-padding must not apply to the health check.
        saved_no_padding = self.no_padding
        self.no_padding = False
        try:
            for attempt in range(3):
                packet = self.build_packet(fuzz_target=None, mode='clean')
                try:
                    resp = self.send_and_recv(packet, timeout=self.timeout)
                except ConnectionRefusedError:
                    return False
                if resp:
                    return True
                time.sleep(0.1)
            return False
        finally:
            self.no_padding = saved_no_padding

    # =========================================================================
    # ARGUMENT PARSING
    # =========================================================================

    def parse_arguments(self, args=None):
        parser = argparse.ArgumentParser(
            description='QUIC Initial Packet Fuzzer - OffByWon Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s --self-test
  %(prog)s -s ::1 -p 4433 --dry-run -n1
  %(prog)s -s ::1 -p 4433 -f --fuzz-target header
  %(prog)s -s ::1 -p 4433 -f --fuzz-len --fuzz-target crypto_frame
  %(prog)s -s ::1 -p 4433 -f --fuzz-target tls
  %(prog)s -s ::1 -p 4433 -f --combined --fuzz-target all
""")
        tg = parser.add_argument_group('Target')
        tg.add_argument("-s", "--server", help="QUIC server hostname or IP")
        tg.add_argument("-p", "--port", type=int, default=4433, help="UDP port (default 4433)")
        tg.add_argument("--timeout", type=float, default=1.0,
                        help="Liveness/baseline response wait in seconds (default 1.0)")
        tg.add_argument("--send-timeout", type=float, default=0.25,
                        help="Per-fuzz-packet response drain in seconds (default 0.25)")
        tg.add_argument("--alpn", default="hq-29", help="ALPN protocol (default hq-29, quinn example)")
        tg.add_argument("--sni", default="localhost", help="TLS SNI / server name")
        tg.add_argument("--v2", action="store_true", help="Use QUIC v2 (RFC 9369) Initial salt/labels")

        fg = parser.add_argument_group('Fuzzing')
        fg.add_argument("-f", "--fuzz", action="store_true", help="Enable structured fuzzing")
        fg.add_argument("--fuzz-target", default="all",
                        choices=self.get_available_targets() + ['all'],
                        help=f"Target: {', '.join(self.get_available_targets())} or 'all'")
        fg.add_argument(
            "--fuzz-count", type=int, default=None,
            help="Maximum structured fields per packet",
        )
        fg.add_argument("--byteflip-count", type=int, default=None,
                        help="Final-datagram byteflips (default: --fuzz-count when set, otherwise 1)")
        fg.add_argument("--blind", action="store_true", help="Blind datagram corruption")
        fg.add_argument("--combined", action="store_true",
                        help="Structured fuzzing plus final-datagram byteflips")
        fg.add_argument("--byteflip", action="store_true", help="Byteflip the final datagram")
        fg.add_argument("--fuzz-len", action="store_true", help="Length/offset mismatch fuzzing")
        fg.add_argument("--no-padding", action="store_true",
                        help="Do not pad to 1200 bytes (tests amplification limit handling)")

        eg = parser.add_argument_group('Execution')
        eg.add_argument("-n", "--iterations", type=int, default=None, help="Iterations (default: infinite)")
        eg.add_argument("--liveness-every", type=int, default=200,
                        help="Run a liveness probe every N packets (default 200)")
        eg.add_argument("--print-every", type=int, default=2000,
                        help="Print a full sample packet block every N packets (default 2000)")
        eg.add_argument("--dry-run", action="store_true", help="Send clean packets only")
        eg.add_argument("-v", "--verbose", action="store_true",
                        help="Print every packet block (very noisy)")
        eg.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress the live status line (only periodic samples + summary)")
        eg.add_argument("--self-test", action="store_true",
                        help="Validate crypto vs RFC 9001 Appendix A and exit")

        p = parser.parse_args(args)

        if p.self_test:
            return p

        if not p.server:
            parser.error("the following argument is required for network fuzzing: -s/--server "
                         "(or use --self-test)")

        if p.fuzz_count is not None and p.fuzz_count < 0:
            parser.error("--fuzz-count cannot be negative")
        if p.byteflip_count is not None and p.byteflip_count < 0:
            parser.error("--byteflip-count cannot be negative")

        self.host = p.server
        self.port = p.port
        self.timeout = p.timeout
        self.send_timeout = p.send_timeout
        self.alpn = p.alpn.encode()
        self.server_name = p.sni
        self.version = QUIC_VERSION_2 if p.v2 else QUIC_VERSION_1

        self.fuzzing = p.fuzz
        self.fuzz_targets = [p.fuzz_target] if p.fuzz_target != 'all' else ['all']
        self.fuzz_count = p.fuzz_count
        if p.byteflip_count is not None:
            self.byteflip_count = p.byteflip_count
        elif p.fuzz_count is not None:
            self.byteflip_count = p.fuzz_count
        else:
            self.byteflip_count = 1
        self.blind_mode = p.blind
        self.combined_mode = p.combined
        self.byteflip_mode = p.byteflip
        self.fuzz_len_mode = p.fuzz_len
        self.no_padding = p.no_padding
        self.iterations = p.iterations
        self.liveness_every = p.liveness_every
        self.print_every = p.print_every
        self.dry_run = p.dry_run
        self.verbose = p.verbose
        self.quiet = p.quiet

        if self.dry_run:
            self.fuzz_mode = 'clean'
        elif self.blind_mode:
            self.fuzz_mode = 'blind'
        elif self.combined_mode:
            self.fuzz_mode = 'combined'
        elif self.byteflip_mode:
            self.fuzz_mode = 'byteflip'
        elif self.fuzz_len_mode:
            self.fuzz_mode = 'length'
        elif self.fuzzing:
            self.fuzz_mode = 'field'
        else:
            self.fuzz_mode = 'clean'

        return p

    # =========================================================================
    # SELF TEST (RFC 9001 Appendix A.2)
    # =========================================================================

    @staticmethod
    def self_test() -> bool:
        print("[*] Self-test: validating Initial crypto against RFC 9001 Appendix A.2...")
        dcid = bytes.fromhex("8394c8f03e515708")
        c = QUICInitialCrypto(dcid, QUIC_VERSION_1)
        checks = {
            "client_secret": ("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", c.client_secret),
            "key": ("1f369613dd76d5467730efcbe3b1a22d", c.key),
            "iv": ("fa044b2f42a3fd3b46fb255c", c.iv),
            "hp": ("9f50449e04a0e810283a1e9933adedd2", c.hp),
        }
        ok = True
        for name, (exp, got) in checks.items():
            good = got.hex() == exp
            ok &= good
            print(f"    {name:14s}: {'OK  ' if good else 'FAIL'} {got.hex()}")

        # Full A.2 protected-packet prefix check.
        crypto_frame = bytes.fromhex(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
            "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
            "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
            "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
            "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
            "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
            "75300901100f088394c8f03e51570806048000ffff")
        payload = crypto_frame + b"\x00" * (1162 - len(crypto_frame))
        header = (bytes([0xc3]) + struct.pack(">I", 1) + bytes([8]) + dcid +
                  bytes([0]) + encode_varint(0) + encode_varint(4 + len(payload) + 16) +
                  (2).to_bytes(4, "big"))
        packet = c.protect(header, payload, pn=2, pn_len=4)
        expected_prefix = "c000000001088394c8f03e5157080000449e7b9aec34d1"
        good = packet[:23].hex() == expected_prefix
        ok &= good
        print(f"    protected pkt : {'OK  ' if good else 'FAIL'} {packet[:23].hex()}")
        print(f"    expected      :      {expected_prefix}")
        print(f"[{'+' if ok else '!'}] Self-test {'PASSED' if ok else 'FAILED'}")
        return ok

    # =========================================================================
    # MAIN RUN LOOP
    # =========================================================================

    def select_target(self) -> Optional[str]:
        # Blind and byteflip modes mutate only the final datagram. Structured
        # targets apply to field, length, combined, and full modes.
        if self.dry_run or self.fuzz_mode not in ('field', 'length', 'combined', 'full'):
            return None
        if 'all' in self.fuzz_targets:
            return random.choice(self.get_available_targets())
        return self.fuzz_targets[0]

    def run(self):
        print(BANNER)
        p = self.parse_arguments()

        if p.self_test:
            sys.exit(0 if self.self_test() else 1)

        print(f"[*] Target:     {self.host}:{self.port} (UDP)")
        print(f"[*] QUIC ver:   0x{self.version:08x}")
        print(f"[*] ALPN:       {self.alpn.decode(errors='replace')}  SNI: {self.server_name}")
        print(f"[*] Mode:       {self.fuzz_mode}")
        print(f"[*] Targets:    {', '.join(self.fuzz_targets)}")
        if self.fuzz_mode in ('field', 'length', 'combined', 'full'):
            structured_count = self.fuzz_count if self.fuzz_count is not None else 'auto (1-5)'
            print(f"[*] Structured: {structured_count} field(s) per packet")
        if self.fuzz_mode in ('byteflip', 'combined', 'full'):
            print(f"[*] Byteflips:  {self.byteflip_count} per packet")
        print(f"[*] Iterations: {'infinite (Ctrl+C to stop)' if self.iterations is None else self.iterations}")
        print()

        self.connect()

        # Baseline correctness check: not just "got a datagram", but "did the
        # server accept our Initial and progress the handshake". We decrypt the
        # reply and classify its frames.
        print("[*] Baseline check (clean valid Initial -> decode server reply)...")
        saved_np = self.no_padding
        self.no_padding = False
        try:
            probe = self.build_packet(fuzz_target=None, mode='clean')
            crypto = self._last_crypto
            try:
                resp = self.send_and_recv(probe, timeout=self.timeout)
            except ConnectionRefusedError:
                resp = None
        finally:
            self.no_padding = saved_np

        if not resp:
            print("[!] No response to clean Initial. Check host/port/ALPN/SNI. Continuing.")
        else:
            verdict = self.classify_server_initial(resp, crypto)
            if verdict == 'handshake':
                print(f"[+] Baseline OK: server returned a ServerHello "
                      f"(CRYPTO frame) - handshake is progressing. ({len(resp)} bytes)")
            elif verdict.startswith('close:'):
                code = verdict.split(':', 1)[1]
                print(f"[!] Baseline DEGRADED: server replied with CONNECTION_CLOSE "
                      f"(error {code}). Our Initial was parsed but REJECTED - the "
                      f"ClientHello/transport params are not fully valid.")
            else:
                print(f"[*] Baseline: server responded ({len(resp)} bytes), reply "
                      f"classified as '{verdict}'.")

        if self.dry_run:
            print("[*] --dry-run: baseline complete, not fuzzing.")
            self.disconnect()
            return

        print(f"[*] Fuzzing... (live status below; full sample packet every "
              f"{self.print_every}; liveness probe every {self.liveness_every})\n")
        self._start_time = time.monotonic()

        try:
            i = 0
            while self.iterations is None or i < self.iterations:
                target = self.select_target()
                try:
                    packet = self.build_packet(fuzz_target=target, mode=self.fuzz_mode)
                    self.packet_count += 1
                    self._target_counts[target or 'clean'] = \
                        self._target_counts.get(target or 'clean', 0) + 1

                    # Full packet block: first few + every print_every, plus -v.
                    if self.verbose or self.packet_count <= 3 or \
                            (self.print_every and self.packet_count % self.print_every == 0):
                        self._clear_status()
                        self._print_packet_output(f"QUIC-Initial[{target or 'clean'}]",
                                                  self.fuzz_mode, packet)

                    last_resp = self.fuzz_send(packet)
                    self.response_count += last_resp

                    # Periodic liveness verification.
                    if self.packet_count % self.liveness_every == 0:
                        if not self.is_alive():
                            self.consecutive_dead += 1
                            self._clear_status()
                            print(f"\n[!!!] LIVENESS PROBE FAILED after packet #{self.packet_count} "
                                  f"(target={target}). Possible crash/hang!")
                            print(f"      Last fuzzed packet hex: {packet.hex()}")
                            self.crash_count += 1
                            if self.consecutive_dead >= 2:
                                print("[!!!] Server unresponsive on consecutive probes - stopping.")
                                break
                        else:
                            self.consecutive_dead = 0

                    self._status_line(target, last_resp)
                    i += 1

                except ConnectionRefusedError:
                    self._clear_status()
                    print(f"\n[!!!] ICMP port-unreachable after packet #{self.packet_count} "
                          f"(target={target}). Server process likely DEAD!")
                    print(f"      Crashing packet hex: {packet.hex()}")
                    self.crash_count += 1
                    if not self.is_alive():
                        print("[!!!] Confirmed dead. Stopping.")
                        break
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    self._clear_status()
                    print(f"\n[!] Builder/transport error: {type(e).__name__}: {e}")
                    i += 1

        except KeyboardInterrupt:
            self._clear_status()
            print("\n[*] Interrupted by user")
        finally:
            self.disconnect()

        self._clear_status()
        elapsed = max(1e-6, time.monotonic() - self._start_time)
        print(f"\n[*] Fuzzing complete.")
        print(f"[*] Packets sent:      {self.packet_count}  "
              f"({self.packet_count / elapsed:.0f}/s over {elapsed:.1f}s)")
        print(f"[*] Responses seen:    {self.response_count}")
        print(f"[*] Potential crashes: {self.crash_count}")
        if self._target_counts:
            spread = "  ".join(f"{t}={n}" for t, n in sorted(self._target_counts.items()))
            print(f"[*] Target spread:     {spread}")


def main():
    QUICInitialFuzzer().run()


if __name__ == "__main__":
    main()

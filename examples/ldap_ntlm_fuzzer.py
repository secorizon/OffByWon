#!/usr/bin/env python3
"""
LDAP NTLM Authentication Fuzzer
================================

A comprehensive example demonstrating how to build a protocol fuzzer using the
OffByWon framework. This fuzzer targets LDAP servers using NTLM authentication.

This example shows:
1. How to integrate OffByWon's mutation primitives into a handwritten encoder
2. How to implement multi-step authentication protocols
3. How to handle BER/DER encoded structures (LDAP)
4. How to implement NTLM authentication with proper cryptography

For a declarative Packet/Field example, see ``quic_initial_fuzzer.py``.

Protocol Flow:
    Client                          Server
      |                               |
      |--- NTLM Type 1 (Negotiate) -->|
      |                               |
      |<-- NTLM Type 2 (Challenge) ---|
      |                               |
      |--- NTLM Type 3 (Auth) ------->|
      |                               |
      |<-- Bind Response -------------|

OffByWon Fuzzing Framework
Author: Laurent Gaffié
Website: https://secorizon.com
Twitter: @secorizon

Usage:
    # Basic NTLM bind (no fuzzing, verify connectivity and packet integrity)
    python3 ldap_ntlm_fuzzer.py -s 192.168.8.109 --username 'testing' --password 'test' --domain smb3 --dry-run -n1

    # Structured fuzz on NTLM Type 1 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target ntlm_type1

    # Structured fuzz on NTLM Type 3 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target ntlm_type3

    # Structured fuzz all NTLM messages
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target all

    # Structured Length mismatch testing on NTLM messages
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-len --fuzz-target all

    # Blind fuzzing (random mutations) (truncate/insert bytes at random offsets, etc)
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --blind
    
    # Structured fuzzing with byteflip (structured field testing + byte flip)
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --combined --fuzz-target ntlm_type1

    # Byteflip only NTLM Type 3 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --fuzz-target ntlm_type3 --fuzz-count 2 --byteflip

    # BER bruteforce scan on LDAP NTLM structure
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --fuzz-target ntlm_type3 --ber-bruteforce --timeout 0.3
"""

import socket
import struct
import hashlib
import hmac
import os
import sys
import time
import argparse
import random
from typing import Optional, Tuple, List, Dict, Any

# =============================================================================
# IMPORT THE OFFBYWON FRAMEWORK
# =============================================================================
# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offbywon import (
    FieldType, encode_der_length,
    get_fuzz_integer, get_fuzz_buffer,
    LENGTH_DELTAS,
)


# =============================================================================
# BANNER
# =============================================================================

BANNER = """
   ____  __  __ ____        _       __           
  / __ \\/ /_/ _/ __ )__  __| |     / /___  ____  
 / / / / __/ /_/ __  / / / / | /| / / __ \\/ __ \\ 
/ /_/ / /_/ __/ /_/ / /_/ /| |/ |/ / /_/ / / / / 
\\____/\\__/_/ /_____/\\__, / |__/|__/\\____/_/ /_/  
                   /____/                         
    LDAP NTLM Authentication Fuzzer
    OffByWon Framework v2.0
"""


# =============================================================================
# LDAP NTLM FUZZER CLASS
# =============================================================================

class LDAPNTLMFuzzer:
    """
    LDAP NTLM Authentication Fuzzer using OffByWon Framework.
    
    This class demonstrates comprehensive protocol fuzzing:
    - Multi-step authentication (Type 1 → Type 2 → Type 3)
    - BER/DER encoding for LDAP
    - NTLM cryptography (MD4, HMAC-MD5, RC4)
    - Multiple fuzzing modes (field, blind, combined, byteflip, BER bruteforce)
    - Length mismatch testing for off-by-one vulnerabilities
    """
    
    def __init__(self):
        """Initialize the fuzzer."""
        # Connection settings
        self.host: str = None
        self.port: int = 389
        self.sock: socket.socket = None
        self.timeout: float = 5.0
        
        # NTLM credentials
        self.domain: str = "WORKGROUP"
        self.username: str = "administrator"
        self.password: str = "password"
        self.workstation: str = "FUZZER"
        
        # LDAP state
        self.message_id: int = 1
        
        # Fuzzing settings
        self.fuzzing: bool = False
        self.fuzz_targets: List[str] = ['all']
        self.fuzz_mode: str = 'field'
        self.fuzz_count: int = None
        self.blind_mode: bool = False
        self.combined_mode: bool = False
        self.byteflip_mode: bool = False
        self.fuzz_len_mode: bool = False
        self.dry_run: bool = False
        self.verbose: bool = False
        self.iterations: Optional[int] = None
        
        # BER bruteforce mode
        self.ber_bruteforce: bool = False
        
        # Statistics
        self.packet_count: int = 0
        self.crash_count: int = 0
        
        # Current packet mutation tracking
        self._current_mutations: List[Tuple[str, Any, Any, str]] = []
        self._current_byteflips: List[Tuple[int, int, int]] = []
    
    # =========================================================================
    # OFFBYWON OUTPUT FORMAT
    # =========================================================================
    
    def _print_packet_output(self, packet_name: str, mode: str, data: bytes):
        """Print standardized OffByWon output for a packet."""
        # Colors
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        DIM = '\033[2m'
        
        print()
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}[OffByWon]{RESET} {BOLD}PACKET #{self.packet_count}{RESET}")
        print(f"Type: {YELLOW}{packet_name}{RESET} | Mode: {GREEN}{mode}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        
        if self._current_mutations:
            print(f"{BOLD}Mutations:{RESET}")
            for field, orig, fuzzed, strategy in self._current_mutations:
                orig_str = self._format_value(orig)
                fuzz_str = self._format_value(fuzzed)
                print(f"  {GREEN}→{RESET} {field}: {DIM}{orig_str}{RESET} → {YELLOW}{fuzz_str}{RESET} ({strategy})")
        
        if self._current_byteflips:
            print(f"{BOLD}Byteflip:{RESET} {len(self._current_byteflips)} mutations")
            for offset, orig, fuzzed in self._current_byteflips[:5]:
                print(f"  {GREEN}→{RESET} offset {offset}: {DIM}0x{orig:02x}{RESET} → {YELLOW}0x{fuzzed:02x}{RESET}")
            if len(self._current_byteflips) > 5:
                print(f"  {DIM}→ ... and {len(self._current_byteflips) - 5} more{RESET}")
        
        if not self._current_mutations and not self._current_byteflips:
            print(f"{DIM}Mutations: none (clean packet){RESET}")
        
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"Size: {len(data)} bytes")
        
        # Hex dump (truncated)
        hex_str = data.hex()
        if len(hex_str) > 100:
            hex_str = hex_str[:100] + f'{DIM}...{RESET}'
        print(f"Hex: {DIM}{hex_str}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
    
    def _format_value(self, value: Any) -> str:
        """Format a value for display."""
        if isinstance(value, bytes):
            if len(value) > 16:
                return f"({len(value)} bytes)"
            return value.hex()
        elif isinstance(value, int):
            if value > 0xFFFF:
                return f"0x{value:x}"
            elif value > 255:
                return f"{value} (0x{value:x})"
            return str(value)
        elif isinstance(value, str):
            if len(value) > 20:
                return f'"{value[:20]}..."'
            return f'"{value}"'
        else:
            return str(value)
    
    def _add_mutation(self, field: str, original: Any, fuzzed: Any, strategy: str):
        """Track a mutation for output."""
        self._current_mutations.append((field, original, fuzzed, strategy))
    
    def _reset_mutations(self):
        """Reset mutation tracking for next packet."""
        self._current_mutations = []
        self._current_byteflips = []
    
    # =========================================================================
    # AVAILABLE FUZZ TARGETS
    # =========================================================================
    
    @staticmethod
    def get_available_targets() -> List[str]:
        """Return list of fuzz targets."""
        return [
            "ntlm_type1",   # NTLM Negotiate message
            "ntlm_type3",   # NTLM Authenticate message
        ]
    
    # =========================================================================
    # ARGUMENT PARSING
    # =========================================================================
    
    def parse_arguments(self, args=None) -> argparse.Namespace:
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(
            description='LDAP NTLM Authentication Fuzzer - OffByWon Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic connectivity test (no fuzzing)
  %(prog)s -s 192.168.1.100 --username user --password pass --dry-run -n1

  # Field-level fuzzing on Type 1
  %(prog)s -s 192.168.1.100 --username user --password pass -f --fuzz-target ntlm_type1

  # Combined fuzzing (field + byteflip)
  %(prog)s -s 192.168.1.100 --username user --password pass -f --combined

  # Length mismatch testing
  %(prog)s -s 192.168.1.100 --username user --password pass -f --fuzz-len

  # BER bruteforce
  %(prog)s -s 192.168.1.100 --username user --password pass --ber-bruteforce --timeout 0.3
"""
        )
        
        # Target specification
        target_group = parser.add_argument_group('Target')
        target_group.add_argument("-s", "--server", required=True,
                                  help="LDAP server hostname or IP")
        target_group.add_argument("-p", "--port", type=int, default=389,
                                  help="LDAP server port (default: 389)")
        target_group.add_argument("--timeout", type=float, default=5.0,
                                  help="Socket timeout in seconds (default: 5.0)")
        
        # NTLM credentials
        cred_group = parser.add_argument_group('Credentials')
        cred_group.add_argument("--domain", default="WORKGROUP",
                                help="NTLM domain (default: WORKGROUP)")
        cred_group.add_argument("--username", default="administrator",
                                help="NTLM username (default: administrator)")
        cred_group.add_argument("--password", default="password",
                                help="NTLM password (default: password)")
        cred_group.add_argument("--workstation", default="FUZZER",
                                help="Workstation name (default: FUZZER)")
        
        # Fuzzing options
        fuzz_group = parser.add_argument_group('Fuzzing')
        fuzz_group.add_argument("-f", "--fuzz", action="store_true",
                                help="Enable structured fuzzing")
        fuzz_group.add_argument("--fuzz-target", default="all",
                                help=f"Fuzz target: {', '.join(self.get_available_targets())} or 'all' (default: all)")
        fuzz_group.add_argument("--fuzz-count", type=int, default=None,
                                help="Max fields to fuzz per packet (default: auto)")
        fuzz_group.add_argument("--blind", action="store_true",
                                help="Blind fuzzing mode (random byte mutations)")
        fuzz_group.add_argument("--combined", action="store_true",
                                help="Combined mode (field fuzzing + byteflip)")
        fuzz_group.add_argument("--byteflip", action="store_true",
                                help="Byteflip mode only")
        fuzz_group.add_argument("--fuzz-len", action="store_true",
                                help="Length mismatch fuzzing (off-by-one testing)")
        fuzz_group.add_argument("--ber-bruteforce", action="store_true",
                                help="BER/ASN.1 byte bruteforce scanning")
        
        # Execution options
        exec_group = parser.add_argument_group('Execution')
        exec_group.add_argument("-n", "--iterations", type=int, default=None,
                                help="Number of fuzzing iterations (default: infinite)")
        exec_group.add_argument("--dry-run", action="store_true",
                                help="Send clean packets only (no fuzzing)")
        exec_group.add_argument("-v", "--verbose", action="store_true",
                                help="Verbose output")
        
        parsed = parser.parse_args(args)
        
        # Store values
        self.host = parsed.server
        self.port = parsed.port
        self.timeout = parsed.timeout
        self.domain = parsed.domain
        self.username = parsed.username
        self.password = parsed.password
        self.workstation = parsed.workstation
        
        self.fuzzing = parsed.fuzz
        self.fuzz_targets = [parsed.fuzz_target] if parsed.fuzz_target != 'all' else ['all']
        self.fuzz_count = parsed.fuzz_count
        self.blind_mode = parsed.blind
        self.combined_mode = parsed.combined
        self.byteflip_mode = parsed.byteflip
        self.fuzz_len_mode = parsed.fuzz_len
        self.ber_bruteforce = parsed.ber_bruteforce
        
        self.iterations = parsed.iterations
        self.dry_run = parsed.dry_run
        self.verbose = parsed.verbose
        
        # Determine fuzz mode
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
        
        return parsed
    
    # =========================================================================
    # LOGGING
    # =========================================================================
    
    def log(self, message: str, level: str = "VERBOSE"):
        """Log a message."""
        if level == "ALWAYS" or (level == "VERBOSE" and self.verbose):
            print(message)
    
    # =========================================================================
    # CONNECTION HANDLING
    # =========================================================================
    
    def connect(self):
        """Establish TCP connection to the LDAP server."""
        self.log(f"[*] Connecting to {self.host}:{self.port}...", "VERBOSE")
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        
        self.log(f"[+] Connected to {self.host}:{self.port}", "VERBOSE")
    
    def disconnect(self):
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def receive_response(self, size: int = 8192) -> Optional[bytes]:
        """Receive response from server."""
        try:
            return self.sock.recv(size)
        except socket.timeout:
            self.log("[!] Timeout waiting for response", "VERBOSE")
            return None
        except Exception as e:
            self.log(f"[!] Receive error: {e}", "VERBOSE")
            return None
    
    # =========================================================================
    # FUZZING HELPERS
    # =========================================================================
    
    def should_fuzz(self, target: str) -> bool:
        """Check if a target should be fuzzed."""
        if self.dry_run:
            return False
        if not self.fuzzing and not self.blind_mode and not self.combined_mode and not self.byteflip_mode:
            return False
        if 'all' in self.fuzz_targets:
            return True
        return target in self.fuzz_targets
    
    def get_fuzz_mode(self, target: str) -> str:
        """Get the fuzzing mode for a target."""
        if not self.should_fuzz(target):
            return 'clean'
        return self.fuzz_mode
    
    def apply_blind_fuzzing(self, data: bytes) -> bytes:
        """Apply blind fuzzing mutations to packet data."""
        if not self.blind_mode or len(data) == 0:
            return data
        
        data = bytearray(data)
        
        # Random mutation strategy
        strategy = random.choice(['truncate', 'extend', 'corrupt', 'insert', 'shuffle'])
        
        if strategy == 'truncate':
            # Truncate at random point
            cut = random.randint(1, len(data))
            data = data[:cut]
            self.log(f"    [BLIND] Truncated to {cut} bytes", "VERBOSE")
        
        elif strategy == 'extend':
            # Extend with random or pattern data
            extra_len = random.randint(1, 1000)
            pattern = random.choice([b'\x00', b'\x41', b'\xff'])
            data.extend(pattern * extra_len)
            self.log(f"    [BLIND] Extended by {extra_len} bytes", "VERBOSE")
        
        elif strategy == 'corrupt':
            # Corrupt random bytes
            num_corruptions = random.randint(1, min(10, len(data)))
            for _ in range(num_corruptions):
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
            self.log(f"    [BLIND] Corrupted {num_corruptions} bytes", "VERBOSE")
        
        elif strategy == 'insert':
            # Insert random bytes at random position
            pos = random.randint(0, len(data))
            insert_len = random.randint(1, 100)
            insert_data = bytes(random.randint(0, 255) for _ in range(insert_len))
            data = data[:pos] + bytearray(insert_data) + data[pos:]
            self.log(f"    [BLIND] Inserted {insert_len} bytes at offset {pos}", "VERBOSE")
        
        elif strategy == 'shuffle':
            # Shuffle a region
            if len(data) > 10:
                start = random.randint(0, len(data) - 10)
                length = random.randint(2, min(50, len(data) - start))
                region = list(data[start:start + length])
                random.shuffle(region)
                data[start:start + length] = region
                self.log(f"    [BLIND] Shuffled {length} bytes at offset {start}", "VERBOSE")
        
        return bytes(data)
    
    def apply_byteflip(self, data: bytes, count: int = None) -> Tuple[bytes, List[Tuple[int, int, int]]]:
        """Apply byte flips to packet data."""
        if len(data) == 0:
            return data, []
        
        if count is None:
            count = random.randint(1, min(5, len(data)))
        
        data = bytearray(data)
        flips = []
        
        positions = random.sample(range(len(data)), min(count, len(data)))
        
        for pos in positions:
            original = data[pos]
            strategy = random.choice(['invert', 'zero', 'ones', 'boundary', 'random'])
            
            if strategy == 'invert':
                fuzzed = original ^ 0xFF
            elif strategy == 'zero':
                fuzzed = 0x00
            elif strategy == 'ones':
                fuzzed = 0xFF
            elif strategy == 'boundary':
                fuzzed = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
            else:
                fuzzed = random.randint(0, 255)
            
            data[pos] = fuzzed
            flips.append((pos, original, fuzzed))
            self.log(f"    [BYTEFLIP] offset {pos}: 0x{original:02x} → 0x{fuzzed:02x}", "VERBOSE")
        
        return bytes(data), flips
    
    # =========================================================================
    # NTLM TYPE 1 (NEGOTIATE) MESSAGE
    # =========================================================================
    
    def build_ntlm_type1(self) -> bytes:
        """
        Build NTLM Type 1 (Negotiate) message wrapped in LDAP SASL bind.
        
        NTLM Type 1 structure:
        - Signature: "NTLMSSP\0"
        - Message Type: 1
        - Negotiate Flags
        - Domain Security Buffer (Len, MaxLen, Offset)
        - Workstation Security Buffer (Len, MaxLen, Offset)
        - Version (optional)
        - Payload (Domain, Workstation)
        """
        self._reset_mutations()
        fuzz = self.should_fuzz('ntlm_type1')
        mode = self.get_fuzz_mode('ntlm_type1')
        
        # Determine how many fields to fuzz (not applicable in blind mode)
        num_fields_to_fuzz = self.fuzz_count if self.fuzz_count else random.randint(1, 3)
        
        # Available fields for fuzzing (excluding length mismatch mode and blind mode)
        fuzzable_fields = [
            'NTLMMessageType', 'NTLMFlags', 'DomainName', 'Workstation',
            'DomainNameOffset', 'WorkstationOffset'
        ]
        
        # Select which fields to fuzz (skip in blind/byteflip - those do raw mutations only)
        fields_to_fuzz = set()
        if fuzz and not self.fuzz_len_mode and not self.blind_mode and not self.byteflip_mode:
            fields_to_fuzz = set(random.sample(fuzzable_fields, min(num_fields_to_fuzz, len(fuzzable_fields))))
        
        # Signature - don't fuzz to keep message recognizable
        signature = b"NTLMSSP\x00"
        
        # Message type
        msg_type = 1
        if 'NTLMMessageType' in fields_to_fuzz:
            fuzzed_type, strategy = get_fuzz_integer(FieldType.DWORD, 1)
            self._add_mutation('NTLMMessageType', 1, fuzzed_type, strategy)
            msg_type = fuzzed_type
        
        # Negotiate flags
        default_flags = 0xe2088297  # Standard NTLMv2 flags
        flags = default_flags
        if 'NTLMFlags' in fields_to_fuzz:
            fuzzed_flags, strategy = get_fuzz_integer(FieldType.DWORD, default_flags)
            self._add_mutation('NTLMFlags', f'0x{default_flags:08x}', f'0x{fuzzed_flags:08x}', strategy)
            flags = fuzzed_flags
        
        # Domain and workstation - Type 1 can have empty or populated
        domain_bytes = b""
        workstation_bytes = b""
        
        if 'DomainName' in fields_to_fuzz:
            domain_bytes = self._fuzz_utf16_string()
            self._add_mutation('DomainName', '(0 bytes)', f'({len(domain_bytes)} bytes)', 'utf16_fuzz')
        
        if 'Workstation' in fields_to_fuzz:
            workstation_bytes = self._fuzz_utf16_string()
            self._add_mutation('Workstation', '(0 bytes)', f'({len(workstation_bytes)} bytes)', 'utf16_fuzz')
        
        # Calculate offsets - header is 40 bytes (8 + 4 + 4 + 8 + 8 + 8)
        header_len = 40
        domain_offset = header_len
        workstation_offset = header_len + len(domain_bytes)
        
        # Security buffer fields with optional length fuzzing
        domain_len = len(domain_bytes)
        domain_max_len = len(domain_bytes)
        workstation_len = len(workstation_bytes)
        workstation_max_len = len(workstation_bytes)
        
        # Length mismatch fuzzing
        if self.fuzz_len_mode and fuzz:
            delta = random.choice(LENGTH_DELTAS)
            field = random.choice(['DomainNameLen', 'DomainNameMaxLen', 'WorkstationLen', 'WorkstationMaxLen'])
            
            if field == 'DomainNameLen':
                original = domain_len
                domain_len = max(0, min(0xFFFF, domain_len + delta))
                self._add_mutation(field, original, f'{domain_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'DomainNameMaxLen':
                original = domain_max_len
                domain_max_len = max(0, min(0xFFFF, domain_max_len + delta))
                self._add_mutation(field, original, f'{domain_max_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'WorkstationLen':
                original = workstation_len
                workstation_len = max(0, min(0xFFFF, workstation_len + delta))
                self._add_mutation(field, original, f'{workstation_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'WorkstationMaxLen':
                original = workstation_max_len
                workstation_max_len = max(0, min(0xFFFF, workstation_max_len + delta))
                self._add_mutation(field, original, f'{workstation_max_len} (delta {delta:+d})', 'length_mismatch')
        
        # Offset fuzzing (only if selected and not in length mismatch mode)
        if 'DomainNameOffset' in fields_to_fuzz:
            orig = domain_offset
            domain_offset, strategy = get_fuzz_integer(FieldType.DWORD, domain_offset)
            self._add_mutation('DomainNameOffset', orig, domain_offset, strategy)
        
        if 'WorkstationOffset' in fields_to_fuzz:
            orig = workstation_offset
            workstation_offset, strategy = get_fuzz_integer(FieldType.DWORD, workstation_offset)
            self._add_mutation('WorkstationOffset', orig, workstation_offset, strategy)
        
        # Version structure (8 bytes) - Windows 10 Build 17763
        version = struct.pack("<BBHBBBB", 10, 0, 17763, 0, 0, 0, 15)
        
        # Assemble NTLM Type 1
        ntlm_type1 = signature
        ntlm_type1 += struct.pack("<I", msg_type)
        ntlm_type1 += struct.pack("<I", flags)
        ntlm_type1 += struct.pack("<HHI", domain_len, domain_max_len, domain_offset)
        ntlm_type1 += struct.pack("<HHI", workstation_len, workstation_max_len, workstation_offset)
        ntlm_type1 += version
        ntlm_type1 += domain_bytes
        ntlm_type1 += workstation_bytes
        
        # Wrap in LDAP SASL bind
        ldap_packet = self._wrap_in_ldap_sasl_bind(ntlm_type1, fuzz)
        
        # Apply post-build mutations only if this target should be fuzzed
        if fuzz:
            if self.blind_mode:
                ldap_packet = self.apply_blind_fuzzing(ldap_packet)
                self._add_mutation('packet', f'({len(ldap_packet)} bytes)', 'mutated', 'blind')
            
            if self.byteflip_mode or self.combined_mode:
                ldap_packet, flips = self.apply_byteflip(ldap_packet, self.fuzz_count)
                self._current_byteflips = flips
            
            self.packet_count += 1
            self._print_packet_output('NTLM_Type1', mode, ldap_packet)
        
        return ldap_packet
    
    # =========================================================================
    # NTLM TYPE 3 (AUTHENTICATE) MESSAGE
    # =========================================================================
    
    def build_ntlm_type3(self, lm_response: bytes, nt_response: bytes, 
                         session_key: bytes) -> bytes:
        """
        Build NTLM Type 3 (Authenticate) message wrapped in LDAP SASL bind.
        
        NTLM Type 3 structure:
        - Signature: "NTLMSSP\0"
        - Message Type: 3
        - LM Response Security Buffer
        - NT Response Security Buffer
        - Domain Security Buffer
        - User Security Buffer
        - Workstation Security Buffer
        - Encrypted Session Key Security Buffer
        - Negotiate Flags
        - Version
        - MIC (optional)
        - Payload data
        """
        self._reset_mutations()
        fuzz = self.should_fuzz('ntlm_type3')
        mode = self.get_fuzz_mode('ntlm_type3')
        
        # Determine how many fields to fuzz (not applicable in blind mode)
        num_fields_to_fuzz = self.fuzz_count if self.fuzz_count else random.randint(1, 3)
        
        # Available fields for fuzzing (excluding length mismatch mode and blind mode)
        fuzzable_fields = [
            'NTLMMessageType', 'NTLMFlags',
            'LmResponse', 'NtResponse', 'DomainName', 'UserName', 'Workstation', 'SessionKey'
        ]
        
        # Select which fields to fuzz (skip in blind/byteflip - those do raw mutations only)
        fields_to_fuzz = set()
        if fuzz and not self.fuzz_len_mode and not self.blind_mode and not self.byteflip_mode:
            fields_to_fuzz = set(random.sample(fuzzable_fields, min(num_fields_to_fuzz, len(fuzzable_fields))))
        
        # Signature
        signature = b"NTLMSSP\x00"
        
        # Message type
        msg_type = 3
        if 'NTLMMessageType' in fields_to_fuzz:
            fuzzed_type, strategy = get_fuzz_integer(FieldType.DWORD, 3)
            self._add_mutation('NTLMMessageType', 3, fuzzed_type, strategy)
            msg_type = fuzzed_type
        
        # Negotiate flags
        default_flags = 0xe2088297
        flags = default_flags
        if 'NTLMFlags' in fields_to_fuzz:
            fuzzed_flags, strategy = get_fuzz_integer(FieldType.DWORD, default_flags)
            self._add_mutation('NTLMFlags', f'0x{default_flags:08x}', f'0x{fuzzed_flags:08x}', strategy)
            flags = fuzzed_flags
        
        # Prepare payload data
        lm_resp = lm_response
        nt_resp = nt_response
        domain = self.domain.encode("utf-16-le")
        username = self.username.encode("utf-16-le")
        workstation = self.workstation.encode("utf-16-le")
        sess_key = session_key
        
        # Fuzz payload data based on selected fields
        if 'LmResponse' in fields_to_fuzz:
            orig_len = len(lm_response)
            lm_resp, strategy = get_fuzz_buffer(len(lm_response))
            self._add_mutation('LmResponse', f'({orig_len} bytes)', f'({len(lm_resp)} bytes)', strategy)
        
        if 'NtResponse' in fields_to_fuzz:
            orig_len = len(nt_response)
            nt_resp, strategy = get_fuzz_buffer(len(nt_response))
            self._add_mutation('NtResponse', f'({orig_len} bytes)', f'({len(nt_resp)} bytes)', strategy)
        
        if 'DomainName' in fields_to_fuzz:
            orig_domain = self.domain
            domain = self._fuzz_utf16_string()
            self._add_mutation('DomainName', f'"{orig_domain}"', f'({len(domain)} bytes)', 'utf16_fuzz')
        
        if 'UserName' in fields_to_fuzz:
            orig_username = self.username
            username = self._fuzz_utf16_string()
            self._add_mutation('UserName', f'"{orig_username}"', f'({len(username)} bytes)', 'utf16_fuzz')
        
        if 'Workstation' in fields_to_fuzz:
            orig_ws = self.workstation
            workstation = self._fuzz_utf16_string()
            self._add_mutation('Workstation', f'"{orig_ws}"', f'({len(workstation)} bytes)', 'utf16_fuzz')
        
        if 'SessionKey' in fields_to_fuzz:
            orig_len = len(session_key)
            sess_key, strategy = get_fuzz_buffer(16)
            self._add_mutation('SessionKey', f'({orig_len} bytes)', f'({len(sess_key)} bytes)', strategy)
        
        # Calculate offsets
        # Header: 8 (sig) + 4 (type) + 6*8 (buffers) + 4 (flags) + 8 (version) = 72
        header_len = 72
        lm_offset = header_len
        nt_offset = lm_offset + len(lm_resp)
        domain_offset = nt_offset + len(nt_resp)
        username_offset = domain_offset + len(domain)
        workstation_offset = username_offset + len(username)
        session_key_offset = workstation_offset + len(workstation)
        
        # Security buffer lengths
        lm_len = len(lm_resp)
        nt_len = len(nt_resp)
        domain_len = len(domain)
        username_len = len(username)
        workstation_len = len(workstation)
        session_key_len = len(sess_key)
        
        # Length mismatch fuzzing
        if self.fuzz_len_mode and fuzz:
            delta = random.choice(LENGTH_DELTAS)
            fields = ['LmResponseLen', 'NtResponseLen', 'DomainNameLen', 
                     'UserNameLen', 'WorkstationLen', 'SessionKeyLen']
            field = random.choice(fields)
            
            if field == 'LmResponseLen':
                original = lm_len
                lm_len = max(0, min(0xFFFF, lm_len + delta))
                self._add_mutation(field, original, f'{lm_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'NtResponseLen':
                original = nt_len
                nt_len = max(0, min(0xFFFF, nt_len + delta))
                self._add_mutation(field, original, f'{nt_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'DomainNameLen':
                original = domain_len
                domain_len = max(0, min(0xFFFF, domain_len + delta))
                self._add_mutation(field, original, f'{domain_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'UserNameLen':
                original = username_len
                username_len = max(0, min(0xFFFF, username_len + delta))
                self._add_mutation(field, original, f'{username_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'WorkstationLen':
                original = workstation_len
                workstation_len = max(0, min(0xFFFF, workstation_len + delta))
                self._add_mutation(field, original, f'{workstation_len} (delta {delta:+d})', 'length_mismatch')
            elif field == 'SessionKeyLen':
                original = session_key_len
                session_key_len = max(0, min(0xFFFF, session_key_len + delta))
                self._add_mutation(field, original, f'{session_key_len} (delta {delta:+d})', 'length_mismatch')
        
        # Version structure
        version = struct.pack("<BBHBBBB", 10, 0, 17763, 0, 0, 0, 15)
        
        # Assemble NTLM Type 3
        ntlm_type3 = signature
        ntlm_type3 += struct.pack("<I", msg_type)
        ntlm_type3 += struct.pack("<HHI", lm_len, len(lm_resp), lm_offset)
        ntlm_type3 += struct.pack("<HHI", nt_len, len(nt_resp), nt_offset)
        ntlm_type3 += struct.pack("<HHI", domain_len, len(domain), domain_offset)
        ntlm_type3 += struct.pack("<HHI", username_len, len(username), username_offset)
        ntlm_type3 += struct.pack("<HHI", workstation_len, len(workstation), workstation_offset)
        ntlm_type3 += struct.pack("<HHI", session_key_len, len(sess_key), session_key_offset)
        ntlm_type3 += struct.pack("<I", flags)
        ntlm_type3 += version
        
        # Payload
        ntlm_type3 += lm_resp
        ntlm_type3 += nt_resp
        ntlm_type3 += domain
        ntlm_type3 += username
        ntlm_type3 += workstation
        ntlm_type3 += sess_key
        
        # Wrap in LDAP SASL bind
        ldap_packet = self._wrap_in_ldap_sasl_bind(ntlm_type3, fuzz)
        
        # Apply post-build mutations only if this target should be fuzzed
        if fuzz:
            if self.blind_mode:
                ldap_packet = self.apply_blind_fuzzing(ldap_packet)
                self._add_mutation('packet', f'({len(ldap_packet)} bytes)', 'mutated', 'blind')
            
            if self.byteflip_mode or self.combined_mode:
                ldap_packet, flips = self.apply_byteflip(ldap_packet, self.fuzz_count)
                self._current_byteflips = flips
            
            self.packet_count += 1
            self._print_packet_output('NTLM_Type3', mode, ldap_packet)
        
        return ldap_packet
    
    # =========================================================================
    # UTF-16 STRING FUZZING
    # =========================================================================
    
    def _fuzz_utf16_string(self) -> bytes:
        """Generate a fuzzed UTF-16LE string."""
        strategies = [
            'long_string',
            'format_string',
            'null_chars',
            'path_traversal',
            'special_chars',
            'empty',
        ]
        
        strategy = random.choice(strategies)
        
        if strategy == 'long_string':
            length = random.randint(100, 2000)
            text = 'A' * length
            return text.encode('utf-16-le')
        
        elif strategy == 'format_string':
            patterns = ['%s%s%s%s%s', '%x%x%x%x', '%n%n%n%n', '%.1024d', '%p%p%p%p']
            text = random.choice(patterns)
            return text.encode('utf-16-le')
        
        elif strategy == 'null_chars':
            text = 'A\x00B\x00C\x00D'
            return text.encode('utf-16-le')
        
        elif strategy == 'path_traversal':
            patterns = ['..\\', '../', '....//']
            pattern = random.choice(patterns)
            reps = random.randint(10, 50)
            text = pattern * reps
            return text.encode('utf-16-le')
        
        elif strategy == 'special_chars':
            special = ['\uffff', '\ufffe', '\ud800', '\udfff', '\u0000', '\u202e']
            text = ''.join([random.choice(special) for _ in range(random.randint(10, 50))])
            try:
                return text.encode('utf-16-le', errors='surrogatepass')
            except:
                return b'\xff\xfe' * 20
        
        else:  # empty
            return b""
    
    # =========================================================================
    # LDAP/BER ENCODING
    # =========================================================================
    
    def _wrap_in_ldap_sasl_bind(self, ntlm_message: bytes, fuzz: bool = False) -> bytes:
        """
        Wrap an NTLM message in LDAP SASL bind request.
        
        LDAP message structure (BER encoded):
        SEQUENCE {
            MessageID INTEGER,
            BindRequest [APPLICATION 0] {
                version INTEGER,
                name OCTET STRING (empty),
                authentication [3] SaslCredentials {
                    mechanism OCTET STRING ("GSS-SPNEGO"),
                    credentials OCTET STRING (NTLM message)
                }
            }
        }
        """
        # Message ID
        msg_id = self.message_id
        self.message_id += 1
        
        if fuzz and not self.fuzz_len_mode and random.random() < 0.1:
            orig = msg_id
            msg_id, _ = get_fuzz_integer(FieldType.DWORD, msg_id)
            self.log(f"    [FUZZ] MessageID: {orig} → {msg_id}", "VERBOSE")
        
        # LDAP version
        ldap_version = 3
        if fuzz and not self.fuzz_len_mode and random.random() < 0.1:
            ldap_version, _ = get_fuzz_integer(FieldType.BYTE, 3)
            self.log(f"    [FUZZ] LDAPVersion: 3 → {ldap_version}", "VERBOSE")
        
        # Build from inside out
        # SASL mechanism = "GSS-SPNEGO"
        mechanism = b"GSS-SPNEGO"
        mechanism_field = bytes([0x04]) + encode_der_length(len(mechanism)) + mechanism
        
        # SASL credentials = NTLM message
        credentials_field = bytes([0x04]) + encode_der_length(len(ntlm_message)) + ntlm_message
        
        # SASL authentication [3] (context tag, constructed)
        sasl_tag = 0xa3
        if fuzz and not self.fuzz_len_mode and random.random() < 0.1:
            orig = sasl_tag
            sasl_tag, _ = get_fuzz_integer(FieldType.BYTE, sasl_tag)
            self.log(f"    [FUZZ] SASLTag: 0x{orig:02x} → 0x{sasl_tag:02x}", "VERBOSE")
        
        sasl_body = mechanism_field + credentials_field
        sasl_auth = bytes([sasl_tag]) + encode_der_length(len(sasl_body)) + sasl_body
        
        # Empty bind DN
        name_field = bytes([0x04, 0x00])
        
        # BindRequest body: version + name + auth
        bind_body = bytes([0x02, 0x01, ldap_version & 0xff]) + name_field + sasl_auth
        
        # BindRequest [APPLICATION 0]
        bind_tag = 0x60
        if fuzz and not self.fuzz_len_mode and random.random() < 0.1:
            orig = bind_tag
            bind_tag, _ = get_fuzz_integer(FieldType.BYTE, bind_tag)
            self.log(f"    [FUZZ] BindRequestTag: 0x{orig:02x} → 0x{bind_tag:02x}", "VERBOSE")
        
        bind_request = bytes([bind_tag]) + encode_der_length(len(bind_body)) + bind_body
        
        # MessageID as BER INTEGER
        msgid_bytes = self._ber_integer(msg_id)
        
        # Outer SEQUENCE
        seq_body = msgid_bytes + bind_request
        seq_tag = 0x30
        if fuzz and not self.fuzz_len_mode and random.random() < 0.1:
            orig = seq_tag
            seq_tag, _ = get_fuzz_integer(FieldType.BYTE, seq_tag)
            self.log(f"    [FUZZ] SequenceTag: 0x{orig:02x} → 0x{seq_tag:02x}", "VERBOSE")
        
        return bytes([seq_tag]) + encode_der_length(len(seq_body)) + seq_body
    
    def _ber_integer(self, value: int) -> bytes:
        """Encode integer as BER INTEGER."""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        
        value_bytes = []
        temp = value
        while temp > 0:
            value_bytes.insert(0, temp & 0xff)
            temp >>= 8
        
        return bytes([0x02, len(value_bytes)]) + bytes(value_bytes)
    
    # =========================================================================
    # NTLM TYPE 2 PARSING
    # =========================================================================
    
    def _parse_ntlm_type2(self, ldap_response: bytes) -> Tuple[Optional[bytes], Optional[int], Optional[bytes]]:
        """
        Parse NTLM Type 2 (Challenge) from LDAP bind response.
        
        Returns: (challenge, flags, target_info) or (None, None, None) on error
        """
        try:
            # Find NTLMSSP signature
            offset = ldap_response.find(b"NTLMSSP\x00")
            if offset == -1:
                return None, None, None
            
            type2 = ldap_response[offset:]
            if len(type2) < 32:
                return None, None, None
            
            # Verify message type is 2
            msg_type = struct.unpack("<I", type2[8:12])[0]
            if msg_type != 2:
                return None, None, None
            
            # Extract challenge (8 bytes at offset 24)
            challenge = type2[24:32]
            
            # Extract flags (at offset 20)
            flags = struct.unpack("<I", type2[20:24])[0]
            
            # Extract target info if present (offset at bytes 40-48)
            target_info = b""
            if len(type2) >= 48:
                ti_len = struct.unpack("<H", type2[40:42])[0]
                ti_offset = struct.unpack("<I", type2[44:48])[0]
                if ti_offset + ti_len <= len(type2):
                    target_info = type2[ti_offset:ti_offset + ti_len]
            
            self.log(f"[+] Challenge: {challenge.hex()}", "VERBOSE")
            return challenge, flags, target_info
            
        except Exception as e:
            self.log(f"[!] Type 2 parse error: {e}", "VERBOSE")
            return None, None, None
    
    # =========================================================================
    # NTLM CRYPTOGRAPHY
    # =========================================================================
    
    def _md4_pure(self, data: bytes) -> bytes:
        """Pure Python MD4 implementation (fallback for systems without OpenSSL MD4)."""
        def left_rotate(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xffffffff
        
        def F(x, y, z):
            return (x & y) | (~x & z)
        
        def G(x, y, z):
            return (x & y) | (x & z) | (y & z)
        
        def H(x, y, z):
            return x ^ y ^ z
        
        # Initialize hash values
        a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        
        # Pre-processing: adding padding bits
        msg = bytearray(data)
        msg_len = len(data)
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack('<Q', msg_len * 8)
        
        # Process each 64-byte chunk
        for chunk_start in range(0, len(msg), 64):
            chunk = msg[chunk_start:chunk_start + 64]
            M = struct.unpack('<16I', chunk)
            
            A, B, C, D = a0, b0, c0, d0
            
            # Round 1
            for i in range(16):
                if i % 4 == 0:
                    A = left_rotate((A + F(B, C, D) + M[i]) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + F(A, B, C) + M[i]) & 0xffffffff, 7)
                elif i % 4 == 2:
                    C = left_rotate((C + F(D, A, B) + M[i]) & 0xffffffff, 11)
                else:
                    B = left_rotate((B + F(C, D, A) + M[i]) & 0xffffffff, 19)
            
            # Round 2
            for i in range(16):
                k = (i % 4) * 4 + i // 4
                if i % 4 == 0:
                    A = left_rotate((A + G(B, C, D) + M[k] + 0x5a827999) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + G(A, B, C) + M[k] + 0x5a827999) & 0xffffffff, 5)
                elif i % 4 == 2:
                    C = left_rotate((C + G(D, A, B) + M[k] + 0x5a827999) & 0xffffffff, 9)
                else:
                    B = left_rotate((B + G(C, D, A) + M[k] + 0x5a827999) & 0xffffffff, 13)
            
            # Round 3
            order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in range(16):
                k = order[i]
                if i % 4 == 0:
                    A = left_rotate((A + H(B, C, D) + M[k] + 0x6ed9eba1) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + H(A, B, C) + M[k] + 0x6ed9eba1) & 0xffffffff, 9)
                elif i % 4 == 2:
                    C = left_rotate((C + H(D, A, B) + M[k] + 0x6ed9eba1) & 0xffffffff, 11)
                else:
                    B = left_rotate((B + H(C, D, A) + M[k] + 0x6ed9eba1) & 0xffffffff, 15)
            
            a0 = (a0 + A) & 0xffffffff
            b0 = (b0 + B) & 0xffffffff
            c0 = (c0 + C) & 0xffffffff
            d0 = (d0 + D) & 0xffffffff
        
        return struct.pack('<4I', a0, b0, c0, d0)
    
    def _compute_nt_hash(self, password: str) -> bytes:
        """Compute NT Hash: MD4(UTF-16LE(password))"""
        password_unicode = password.encode("utf-16-le")
        
        # Try OpenSSL MD4 first (faster)
        try:
            return hashlib.new("md4", password_unicode, usedforsecurity=False).digest()
        except (TypeError, ValueError):
            pass
        
        try:
            return hashlib.new("md4", password_unicode).digest()
        except ValueError:
            pass
        
        # Fallback to pure Python implementation
        return self._md4_pure(password_unicode)
    
    def _compute_ntlmv2_hash(self, nt_hash: bytes, username: str, domain: str) -> bytes:
        """Compute NTLMv2 Hash: HMAC-MD5(NT_Hash, uppercase(user) + domain)"""
        user_domain = (username.upper() + domain).encode("utf-16-le")
        return hmac.new(nt_hash, user_domain, "md5").digest()
    
    def _create_client_blob(self, server_challenge: bytes, target_info: bytes) -> bytes:
        """Create NTLMv2 client blob with timestamp."""
        client_challenge = os.urandom(8)
        
        # Windows FILETIME
        unix_time = time.time()
        filetime = int((unix_time + 11644473600) * 10000000)
        
        blob = struct.pack("<BB", 1, 1)       # RespType, HiRespType
        blob += struct.pack("<H", 0)          # Reserved1
        blob += struct.pack("<I", 0)          # Reserved2
        blob += struct.pack("<Q", filetime)   # TimeStamp
        blob += client_challenge              # ClientChallenge
        blob += struct.pack("<I", 0)          # Reserved3
        blob += target_info                   # AvPairs
        blob += struct.pack("<I", 0)          # Reserved4
        
        return blob
    
    def _compute_ntlmv2_response(self, ntlmv2_hash: bytes, server_challenge: bytes, 
                                  client_blob: bytes) -> bytes:
        """Compute NTLMv2 response."""
        temp = server_challenge + client_blob
        nt_proof = hmac.new(ntlmv2_hash, temp, "md5").digest()
        return nt_proof + client_blob
    
    def _rc4_encrypt(self, key: bytes, data: bytes) -> bytes:
        """RC4 encryption for session key."""
        # Key scheduling
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        
        return bytes(result)
    
    # =========================================================================
    # RESPONSE CHECKING
    # =========================================================================
    
    def _check_bind_result(self, response: bytes) -> bool:
        """Check LDAP bind response for success (resultCode = 0)."""
        try:
            # Look for ENUMERATED (0x0a) followed by length 1 and value
            idx = response.find(b"\x0a\x01")
            if idx >= 0 and idx + 2 < len(response):
                result_code = response[idx + 2]
                if result_code == 0:
                    self.log("[+] Authentication SUCCESS!", "VERBOSE")
                    return True
                elif result_code == 14:  # saslBindInProgress (OK for Type 1)
                    return True
                elif result_code == 49:
                    self.log("[!] Authentication FAILED: Invalid credentials", "VERBOSE")
                    return False
                else:
                    self.log(f"[!] LDAP resultCode: {result_code}", "VERBOSE")
                    return False
            return True  # Assume success if we can't parse
        except:
            return True
    
    # =========================================================================
    # NTLM AUTHENTICATION FLOW
    # =========================================================================
    
    def _do_ntlm_auth(self) -> bool:
        """Perform complete NTLM authentication."""
        # Step 1: Send NTLM Type 1 (Negotiate)
        self.log("[*] Sending NTLM Type 1 (Negotiate)...", "VERBOSE")
        type1_packet = self.build_ntlm_type1()
        self.sock.sendall(type1_packet)
        
        # Receive Type 2 (Challenge)
        response = self.receive_response()
        if not response:
            self.log("[!] No Type 2 response received", "VERBOSE")
            return False
        
        self.log(f"[+] Received Type 2 (Challenge): {len(response)} bytes", "VERBOSE")
        
        # Parse the challenge from Type 2
        challenge, flags, target_info = self._parse_ntlm_type2(response)
        if challenge is None:
            self.log("[!] Failed to parse NTLM Type 2", "VERBOSE")
            # Continue anyway for fuzzing - use dummy challenge
            challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            target_info = b""
        
        # Step 2: Compute NTLM responses
        nt_hash = self._compute_nt_hash(self.password)
        ntlmv2_hash = self._compute_ntlmv2_hash(nt_hash, self.username, self.domain)
        
        # Create client blob and compute response
        client_blob = self._create_client_blob(challenge, target_info)
        nt_response = self._compute_ntlmv2_response(ntlmv2_hash, challenge, client_blob)
        lm_response = b"\x00" * 24  # LMv2 not needed
        
        # Compute session key
        nt_proof = nt_response[:16]
        session_base_key = hmac.new(ntlmv2_hash, nt_proof, "md5").digest()
        random_session_key = os.urandom(16)
        encrypted_session_key = self._rc4_encrypt(session_base_key, random_session_key)
        
        # Step 3: Send NTLM Type 3 (Authenticate)
        self.log("[*] Sending NTLM Type 3 (Authenticate)...", "VERBOSE")
        type3_packet = self.build_ntlm_type3(lm_response, nt_response, encrypted_session_key)
        self.sock.sendall(type3_packet)
        
        # Receive final response
        response = self.receive_response()
        if response:
            self.log(f"[+] Received bind response: {len(response)} bytes", "VERBOSE")
            return self._check_bind_result(response)
        else:
            self.log("[!] No bind response", "VERBOSE")
            return False
    
    # =========================================================================
    # BER BRUTEFORCE MODE
    # =========================================================================
    
    def run_ber_bruteforce(self):
        """
        Run BER/ASN.1 bruteforce scanning.
        
        This mode sends a clean packet, then iterates through each byte position,
        trying all 256 values to find parsing bugs.
        """
        self.log("[*] Starting BER bruteforce scan...", "ALWAYS")
        
        # Build a clean base packet
        saved_fuzzing = self.fuzzing
        self.fuzzing = False
        base_packet = self.build_ntlm_type1()
        self.fuzzing = saved_fuzzing
        
        self.log(f"[*] Base packet size: {len(base_packet)} bytes", "ALWAYS")
        
        findings = []
        
        # For each byte position
        for pos in range(len(base_packet)):
            original_byte = base_packet[pos]
            
            # Try each byte value
            for test_value in range(256):
                if test_value == original_byte:
                    continue
                
                # Create mutated packet
                mutated = bytearray(base_packet)
                mutated[pos] = test_value
                mutated = bytes(mutated)
                
                try:
                    if not self.sock:
                        self.connect()
                    
                    self.sock.sendall(mutated)
                    response = self.receive_response()
                    
                    # Analyze response
                    result = self._parse_ber_response(response)
                    
                    # Check for interesting responses
                    if result['status'] not in ['SASL_BIND_IN_PROGRESS', 'PROTOCOL_ERROR']:
                        self.log(f"[!] Pos {pos}: 0x{original_byte:02x}→0x{test_value:02x} = {result['status']}", "ALWAYS")
                        findings.append({
                            'position': pos,
                            'original': original_byte,
                            'fuzzed': test_value,
                            'status': result['status'],
                        })
                    
                    # Reconnect for next test
                    self.disconnect()
                    
                except socket.error as e:
                    self.log(f"[!] Pos {pos}: 0x{original_byte:02x}→0x{test_value:02x} = SOCKET_ERROR ({e})", "VERBOSE")
                    self.disconnect()
                
                except Exception as e:
                    self.log(f"[!] Pos {pos}: Error: {e}", "VERBOSE")
                    self.disconnect()
            
            # Progress indicator
            if pos % 10 == 0:
                self.log(f"[*] Progress: {pos}/{len(base_packet)} bytes scanned", "ALWAYS")
        
        self.log(f"\n[*] BER bruteforce complete. Found {len(findings)} interesting responses.", "ALWAYS")
        return findings
    
    def _parse_ber_response(self, response: Optional[bytes]) -> Dict[str, Any]:
        """Parse LDAP response for BER bruteforce."""
        if response is None:
            return {'status': 'NO_RESPONSE', 'raw_len': 0}
        
        if len(response) == 0:
            return {'status': 'EMPTY', 'raw_len': 0}
        
        result = {'status': 'UNKNOWN', 'raw_len': len(response)}
        
        try:
            # Try to find LDAP result code
            idx = response.find(b"\x0a\x01")
            if idx >= 0 and idx + 2 < len(response):
                result_code = response[idx + 2]
                
                ldap_codes = {
                    0: 'SUCCESS',
                    1: 'OPERATIONS_ERROR',
                    2: 'PROTOCOL_ERROR',
                    7: 'AUTH_METHOD_NOT_SUPPORTED',
                    14: 'SASL_BIND_IN_PROGRESS',
                    49: 'INVALID_CREDENTIALS',
                    50: 'INSUFFICIENT_ACCESS',
                    53: 'UNWILLING_TO_PERFORM',
                }
                
                result['status'] = ldap_codes.get(result_code, f'LDAP_{result_code}')
                result['result_code'] = result_code
            else:
                if response[0] == 0x30:
                    result['status'] = 'BER_SEQUENCE'
                else:
                    result['status'] = f'BYTE_0x{response[0]:02X}'
        except Exception as e:
            result['status'] = 'PARSE_ERROR'
            result['error'] = str(e)
        
        return result
    
    # =========================================================================
    # MAIN FUZZING SESSION
    # =========================================================================
    
    def run_fuzzing_session(self):
        """Run one fuzzing iteration."""
        # Ensure we're connected
        if not self.sock:
            self.connect()
        
        # Perform NTLM authentication
        success = self._do_ntlm_auth()
        
        # Disconnect after each session
        self.disconnect()
        
        return success
    
    # =========================================================================
    # MAIN RUN LOOP
    # =========================================================================
    
    def run(self):
        """Main entry point."""
        print(BANNER)
        
        # Parse arguments
        self.parse_arguments()
        
        print(f"[*] Target: {self.host}:{self.port}")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] Username: {self.username}")
        print(f"[*] Mode: {self.fuzz_mode}")
        print(f"[*] Fuzz targets: {', '.join(self.fuzz_targets)}")
        if self.iterations is None:
            print(f"[*] Iterations: infinite (Ctrl+C to stop)")
        else:
            print(f"[*] Iterations: {self.iterations}")
        
        # BER bruteforce mode
        if self.ber_bruteforce:
            try:
                self.connect()
                self.run_ber_bruteforce()
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
            finally:
                self.disconnect()
            return
        
        # Normal fuzzing loop
        try:
            i = 0
            while self.iterations is None or i < self.iterations:
                try:
                    self.run_fuzzing_session()
                    i += 1
                    
                except socket.error as e:
                    print(f"\n[!] Socket error: {e}")
                    self.crash_count += 1
                    self.disconnect()
                    time.sleep(0.5)  # Brief pause before retry
                
                except Exception as e:
                    print(f"\n[!] Error: {e}")
                    self.disconnect()
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
        
        finally:
            self.disconnect()
        
        # Summary
        print(f"\n[*] Fuzzing complete.")
        print(f"[*] Packets sent: {self.packet_count}")
        print(f"[*] Potential crashes: {self.crash_count}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    fuzzer = LDAPNTLMFuzzer()
    fuzzer.run()


if __name__ == "__main__":
    main()

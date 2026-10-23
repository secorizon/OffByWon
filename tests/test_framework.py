#!/usr/bin/env python3
"""
OffByWon Framework Tests

Verifies all core functionality:
- Field definitions and serialization
- Boundary value coverage
- Length/count/offset resolution
- DER encoding
- Fuzzing modes
- Output formatting
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offbywon import (
    Framework, Packet, Field, Marker, FieldType, FuzzMode,
    BYTE_BOUNDARIES, WORD_BOUNDARIES, DWORD_BOUNDARIES, COUNT_VALUES,
    get_fuzz_integer, get_fuzz_buffer,
    encode_der_sequence, encode_der_integer, encode_der_octet_string,
    encode_der_context, encode_der_application, wrap_der, DERTag,
    build_spnego_init,
    OID_NTLM_RAW,
)


def test_boundary_values():
    """Test that boundary values cover critical edges."""
    print("\n=== Testing Boundary Values ===")
    
    # BYTE boundaries
    assert 0 in BYTE_BOUNDARIES, "BYTE should include 0"
    assert 255 in BYTE_BOUNDARIES, "BYTE should include 255"
    assert 127 in BYTE_BOUNDARIES, "BYTE should include 127 (signed boundary)"
    assert 128 in BYTE_BOUNDARIES, "BYTE should include 128 (signed boundary)"
    
    # WORD boundaries - check new values
    assert 253 in WORD_BOUNDARIES, "WORD should include 253"
    assert 254 in WORD_BOUNDARIES, "WORD should include 254"
    assert 255 in WORD_BOUNDARIES, "WORD should include 255"
    assert 256 in WORD_BOUNDARIES, "WORD should include 256"
    assert 257 in WORD_BOUNDARIES, "WORD should include 257"
    assert 258 in WORD_BOUNDARIES, "WORD should include 258"
    
    # Power of 2 boundaries with +/- 2
    for power in [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]:
        if power <= 65535:
            assert power - 2 in WORD_BOUNDARIES, f"WORD should include {power}-2"
            assert power - 1 in WORD_BOUNDARIES, f"WORD should include {power}-1"
            assert power in WORD_BOUNDARIES, f"WORD should include {power}"
            assert power + 1 in WORD_BOUNDARIES, f"WORD should include {power}+1"
            assert power + 2 in WORD_BOUNDARIES, f"WORD should include {power}+2"
    
    # DWORD boundaries
    for power in [2048, 4096, 65536, 1048576, 16777216, 2147483648]:
        if power <= 0xFFFFFFFF:
            assert power - 2 in DWORD_BOUNDARIES, f"DWORD should include {power}-2"
            assert power in DWORD_BOUNDARIES, f"DWORD should include {power}"
            assert power + 2 in DWORD_BOUNDARIES, f"DWORD should include {power}+2"
    
    # COUNT_VALUES - comprehensive coverage
    assert 552 in COUNT_VALUES, "COUNT should include 552"
    assert 2048 in COUNT_VALUES, "COUNT should include 2048"
    assert 4096 in COUNT_VALUES, "COUNT should include 4096"
    assert 16384 in COUNT_VALUES, "COUNT should include 16384"
    
    print(f"  BYTE boundaries: {len(BYTE_BOUNDARIES)} values")
    print(f"  WORD boundaries: {len(WORD_BOUNDARIES)} values")
    print(f"  DWORD boundaries: {len(DWORD_BOUNDARIES)} values")
    print(f"  COUNT values: {len(COUNT_VALUES)} values")
    print("  ✓ All boundary value tests passed")


def test_simple_packet():
    """Test basic packet definition and serialization."""
    print("\n=== Testing Simple Packet ===")
    
    class TestPacket(Packet):
        fields = [
            Field('version', FieldType.BYTE, 1),
            Field('flags', FieldType.WORD, 0x0000),
            Field('length', FieldType.DWORD, 0),
        ]
    
    fw = Framework(verbose=False)
    
    # Clean build
    data = fw.build_clean(TestPacket, {'version': 2, 'flags': 0x1234})
    assert len(data) == 7, f"Expected 7 bytes, got {len(data)}"
    assert data[0] == 2, "Version should be 2"
    assert data[1:3] == b'\x34\x12', "Flags should be little-endian 0x1234"
    
    print(f"  Clean packet: {data.hex()}")
    print("  ✓ Simple packet test passed")


def test_length_resolution():
    """Test automatic length field resolution."""
    print("\n=== Testing Length Resolution ===")
    
    class LengthPacket(Packet):
        fields = [
            Field('data_length', FieldType.LENGTH, target='data', size_type=FieldType.WORD),
            Field('data', FieldType.BYTES),
        ]
    
    fw = Framework(verbose=False)
    data = fw.build_clean(LengthPacket, {'data': b'Hello World!'})
    
    # First 2 bytes should be length (12)
    length = int.from_bytes(data[:2], 'little')
    assert length == 12, f"Expected length 12, got {length}"
    assert data[2:] == b'Hello World!', "Data should follow length"
    
    print(f"  Packet with length: {data.hex()}")
    print("  ✓ Length resolution test passed")


def test_offset_resolution():
    """Test automatic offset field resolution."""
    print("\n=== Testing Offset Resolution ===")
    
    class OffsetPacket(Packet):
        fields = [
            Marker('start'),
            Field('header', FieldType.DWORD, 0x12345678),
            Field('data_offset', FieldType.OFFSET, target='data', base='start', size_type=FieldType.WORD),
            Field('reserved', FieldType.WORD, 0),
            Field('data', FieldType.BYTES),
        ]
    
    fw = Framework(verbose=False)
    data = fw.build_clean(OffsetPacket, {'data': b'TEST'})
    
    # Offset should be 8 (4 byte header + 2 byte offset + 2 byte reserved)
    offset = int.from_bytes(data[4:6], 'little')
    assert offset == 8, f"Expected offset 8, got {offset}"
    assert data[8:] == b'TEST', "Data should be at offset 8"
    
    print(f"  Packet with offset: {data.hex()}")
    print("  ✓ Offset resolution test passed")


def test_array_serialization():
    """Test array field serialization."""
    print("\n=== Testing Array Serialization ===")
    
    class ArrayPacket(Packet):
        fields = [
            Field('count', FieldType.COUNT, target='items', size_type=FieldType.WORD),
            Field('items', FieldType.ARRAY, element=FieldType.DWORD, element_size=4),
        ]
    
    fw = Framework(verbose=False)
    data = fw.build_clean(ArrayPacket, {'items': [1, 2, 3, 4, 5]})
    
    # Should have 2 byte count + 5 * 4 byte items = 22 bytes
    assert len(data) == 22, f"Expected 22 bytes, got {len(data)}"
    assert int.from_bytes(data[:2], 'little') == 5, "COUNT should match the array"
    
    print(f"  Array packet: {data.hex()}")
    print("  ✓ Array serialization test passed")


def test_nested_structure():
    """Test nested packet structure."""
    print("\n=== Testing Nested Structure ===")
    
    class Inner(Packet):
        fields = [
            Field('value', FieldType.DWORD, 0x41414141),
        ]
    
    class Outer(Packet):
        fields = [
            Field('version', FieldType.BYTE, 1),
            Field('inner', FieldType.STRUCT, element=Inner),
            Field('trailer', FieldType.BYTE, 0xFF),
        ]
    
    fw = Framework(verbose=False)
    data = fw.build_clean(Outer)
    
    assert len(data) == 6, f"Expected 6 bytes, got {len(data)}"
    assert data[0] == 1, "Version should be 1"
    assert data[1:5] == b'\x41\x41\x41\x41', "Inner value should be 0x41414141"
    assert data[5] == 0xFF, "Trailer should be 0xFF"
    
    print(f"  Nested packet: {data.hex()}")
    print("  ✓ Nested structure test passed")


def test_der_encoding():
    """Test DER/ASN.1 encoding."""
    print("\n=== Testing DER Encoding ===")
    
    # INTEGER encoding
    int_der = wrap_der(DERTag.INTEGER, encode_der_integer(256))
    assert int_der == b'\x02\x02\x01\x00', f"Expected 0x02020100, got {int_der.hex()}"
    
    # OCTET STRING
    oct_der = encode_der_octet_string(b'TEST')
    assert oct_der == b'\x04\x04TEST', f"Expected 0x04045445535, got {oct_der.hex()}"
    
    # SEQUENCE
    seq_der = encode_der_sequence([
        wrap_der(DERTag.INTEGER, encode_der_integer(1)),
        encode_der_octet_string(b'A'),
    ])
    assert seq_der[:2] == b'\x30\x06', "SEQUENCE tag and length"
    
    # CONTEXT tagged
    ctx_der = encode_der_context(0, b'test', fuzz=False)
    assert ctx_der[0] == 0xa0, "CONTEXT[0] tag should be 0xa0"
    
    # APPLICATION tagged
    app_der = encode_der_application(0, b'test', fuzz=False)
    assert app_der[0] == 0x60, "APPLICATION[0] tag should be 0x60"
    
    print(f"  INTEGER(256): {int_der.hex()}")
    print(f"  OCTET STRING: {oct_der.hex()}")
    print(f"  CONTEXT[0]: {ctx_der.hex()}")
    print("  ✓ DER encoding test passed")


def test_spnego():
    """Test SPNEGO/GSS-API building."""
    print("\n=== Testing SPNEGO ===")
    
    # Build SPNEGO init with NTLM token
    ntlm_token = b'NTLMSSP\x00' + b'\x00' * 24  # Minimal Type 1
    spnego = build_spnego_init([OID_NTLM_RAW], ntlm_token, fuzz=False)
    
    # Should start with APPLICATION[0]
    assert spnego[0] == 0x60, "SPNEGO should start with APPLICATION[0]"
    
    print(f"  SPNEGO init: {spnego[:32].hex()}...")
    print("  ✓ SPNEGO test passed")


def test_field_fuzzing():
    """Test field-level fuzzing."""
    print("\n=== Testing Field Fuzzing ===")
    
    class FuzzPacket(Packet):
        fields = [
            Field('value', FieldType.DWORD, 100),
            Field('flags', FieldType.WORD, 0),
        ]
    
    fw = Framework(verbose=False)
    
    # Run multiple iterations to verify fuzzing works
    mutations_seen = set()
    for _ in range(100):
        data, info = fw.build(FuzzPacket, mode='field')
        for m in info.mutations:
            mutations_seen.add((m.field, m.strategy))
    
    assert len(mutations_seen) > 0, "Should have seen some mutations"
    print(f"  Mutation types seen: {len(mutations_seen)}")
    
    # Check specific strategies appear
    strategies = {s for _, s in mutations_seen}
    print(f"  Strategies: {strategies}")
    print("  ✓ Field fuzzing test passed")


def test_byteflip():
    """Test byte-level flip fuzzing."""
    print("\n=== Testing Byteflip Fuzzing ===")
    
    class ByteflipPacket(Packet):
        fields = [
            Field('data', FieldType.BYTES, b'\x00' * 64, size=64),
        ]
    
    fw = Framework(verbose=False)
    data, info = fw.build(ByteflipPacket, mode='byteflip', byteflip_count=5)
    
    assert len(info.byteflips) > 0, "Should have byteflips"
    assert any(b != 0 for b in data), "Data should have been modified"
    
    print(f"  Byteflips applied: {len(info.byteflips)}")
    print("  ✓ Byteflip test passed")


def test_ntlm_like_packet():
    """Test NTLM-like packet with security buffers."""
    print("\n=== Testing NTLM-like Packet ===")
    
    class NTLMType1Like(Packet):
        """NTLM-like packet with length/offset security buffers."""
        fields = [
            Marker('ntlm_start'),
            Field('signature', FieldType.BYTES, b'NTLMSSP\x00', size=8, fuzz=False),
            Field('message_type', FieldType.DWORD, 1),
            Field('negotiate_flags', FieldType.DWORD, 0xe2088297),
            Field('domain_len', FieldType.LENGTH, target='domain', size_type=FieldType.WORD),
            Field('domain_max_len', FieldType.LENGTH, target='domain', size_type=FieldType.WORD),
            Field('domain_offset', FieldType.OFFSET, target='domain', base='ntlm_start', size_type=FieldType.DWORD),
            Field('workstation_len', FieldType.LENGTH, target='workstation', size_type=FieldType.WORD),
            Field('workstation_max_len', FieldType.LENGTH, target='workstation', size_type=FieldType.WORD),
            Field('workstation_offset', FieldType.OFFSET, target='workstation', base='ntlm_start', size_type=FieldType.DWORD),
            Field('version', FieldType.BYTES, b'\x0a\x00\x63\x45\x00\x00\x00\x0f', size=8),
            Field('domain', FieldType.STRING, '', encoding='ascii'),
            Field('workstation', FieldType.STRING, '', encoding='ascii'),
        ]
    
    fw = Framework(verbose=False)
    
    data = fw.build_clean(NTLMType1Like, {
        'negotiate_flags': 0xe2088297,
        'domain': '',
        'workstation': '',
    })
    
    # Check NTLM signature
    assert data[:8] == b'NTLMSSP\x00', "Should have NTLM signature"
    assert data[8:12] == b'\x01\x00\x00\x00', "Message type should be 1"
    
    print(f"  NTLM-like Type 1: {data.hex()}")
    print("  ✓ NTLM-like packet test passed")


def test_combined_mode():
    """Test combined fuzzing mode."""
    print("\n=== Testing Combined Mode ===")
    
    class CombinedPacket(Packet):
        fields = [
            Field('magic', FieldType.DWORD, 0x12345678, fuzz=False),
            Field('version', FieldType.BYTE, 1),
            Field('flags', FieldType.DWORD, 0),
            Field('data_length', FieldType.LENGTH, target='data', size_type=FieldType.WORD),
            Field('data', FieldType.BYTES),
        ]
    
    fw = Framework(verbose=True)  # Show output for this one
    
    data, info = fw.build(
        CombinedPacket,
        mode='combined',
        values={
            'version': 1,
            'flags': 0x00000001,
            'data': b'Test payload data',
        },
        fuzz_count=3,
        byteflip_count=2,
    )
    
    print(f"\n  Combined mode: {len(info.mutations)} mutations, {len(info.byteflips)} byteflips")
    print(f"  Original size: {info.original_size}, Fuzzed size: {info.fuzzed_size}")
    print("  ✓ Combined mode test passed")


def test_get_fuzz_integer():
    """Test integer fuzzing helper."""
    print("\n=== Testing get_fuzz_integer ===")
    
    values_seen = set()
    strategies_seen = set()
    
    for _ in range(1000):
        value, strategy = get_fuzz_integer(FieldType.WORD, 100)
        values_seen.add(value)
        strategies_seen.add(strategy)
    
    print(f"  Unique values generated: {len(values_seen)}")
    print(f"  Strategies used: {strategies_seen}")
    
    # Check we're hitting boundaries
    boundary_hits = values_seen & set(WORD_BOUNDARIES)
    print(f"  Boundary values hit: {len(boundary_hits)}")
    
    assert len(strategies_seen) > 3, "Should use multiple strategies"
    assert len(boundary_hits) > 5, "Should hit multiple boundaries"
    
    print("  ✓ get_fuzz_integer test passed")


def test_get_fuzz_buffer():
    """Test buffer fuzzing helper."""
    print("\n=== Testing get_fuzz_buffer ===")
    
    strategies_seen = set()
    
    for _ in range(100):
        buf, strategy = get_fuzz_buffer(64)
        strategies_seen.add(strategy)
    
    print(f"  Strategies used: {strategies_seen}")
    assert 'overflow' in strategies_seen or 'truncate' in strategies_seen or 'empty' in strategies_seen
    
    print("  ✓ get_fuzz_buffer test passed")


def main():
    print("=" * 60)
    print("OffByWon Framework Tests")
    print("=" * 60)
    
    tests = [
        test_boundary_values,
        test_simple_packet,
        test_length_resolution,
        test_offset_resolution,
        test_array_serialization,
        test_nested_structure,
        test_der_encoding,
        test_spnego,
        test_field_fuzzing,
        test_byteflip,
        test_ntlm_like_packet,
        test_get_fuzz_integer,
        test_get_fuzz_buffer,
        test_combined_mode,  # Last since it has verbose output
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

"""
OffByWon Framework - Core Types

Field types, mutation strategies, and boundary-value sets.
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Any, Optional, Dict, Union, Callable, Type, Tuple
import random


class FieldType(Enum):
    """Field type enumeration for packet definitions."""
    
    # Basic integers (little-endian by default)
    BYTE = auto()       # 8-bit unsigned
    SBYTE = auto()      # 8-bit signed
    WORD = auto()       # 16-bit unsigned
    SWORD = auto()      # 16-bit signed
    DWORD = auto()      # 32-bit unsigned
    SDWORD = auto()     # 32-bit signed
    QWORD = auto()      # 64-bit unsigned
    SQWORD = auto()     # 64-bit signed
    
    # Big-endian variants
    WORD_BE = auto()
    DWORD_BE = auto()
    QWORD_BE = auto()
    
    # Variable-length integers
    VARINT = auto()         # QUIC-style variable-length (2-bit length prefix)
    VARINT_SIGNED = auto()  # Zigzag encoding (protobuf)
    ULEB128 = auto()        # Unsigned LEB128 (DWARF, WebAssembly)
    SLEB128 = auto()        # Signed LEB128
    
    # Raw data
    BYTES = auto()          # Raw bytes
    STRING = auto()         # Text with encoding
    GUID = auto()           # 16-byte UUID
    
    # Structural
    LENGTH = auto()         # Byte count of target field
    COUNT = auto()          # Element count of target array
    OFFSET = auto()         # Byte offset to target field
    PADDING = auto()        # Alignment padding
    RESERVED = auto()       # Reserved bytes (fuzzable zeros)
    
    # Compound
    ARRAY = auto()          # Array of elements
    STRUCT = auto()         # Nested packet structure
    UNION = auto()          # One of multiple structures (discriminated)
    
    # DER/ASN.1 (BER-compatible)
    DER_SEQUENCE = auto()
    DER_SET = auto()
    DER_INTEGER = auto()
    DER_OCTET_STRING = auto()
    DER_BIT_STRING = auto()
    DER_OID = auto()
    DER_UTF8_STRING = auto()
    DER_PRINTABLE_STRING = auto()
    DER_IA5_STRING = auto()
    DER_UTC_TIME = auto()
    DER_GENERALIZED_TIME = auto()
    DER_BOOLEAN = auto()
    DER_NULL = auto()
    DER_ENUMERATED = auto()
    DER_CONTEXT = auto()        # CONTEXT[n] tagged
    DER_APPLICATION = auto()    # APPLICATION[n] tagged
    DER_PRIVATE = auto()        # PRIVATE[n] tagged
    DER_ANY = auto()            # Raw DER passthrough
    
    # NDR (DCE-RPC)
    NDR_CONFORMANT = auto()     # Conformant array
    NDR_VARYING = auto()        # Varying array
    NDR_CONFORMANT_VARYING = auto()  # Both


class FuzzMode(Enum):
    """Fuzzing mode enumeration."""
    CLEAN = 'clean'           # No fuzzing
    FIELD = 'field'           # Field-level mutations only
    BLIND = 'blind'           # Random byte corruption
    BYTEFLIP = 'byteflip'     # Targeted byte flips post-serialization
    COMBINED = 'combined'     # Field + byteflip
    LENGTH = 'length'         # Length/count/offset mismatches
    ARRAY = 'array'           # Array expansion/manipulation
    FULL = 'full'             # All strategies combined


# =============================================================================
# Boundary Values
# =============================================================================

# Integer boundaries around power-of-two edges
BYTE_BOUNDARIES = [
    0, 1, 2,                          # Near zero
    62, 63, 64, 65, 66,               # 2^6 boundary
    126, 127, 128, 129, 130,          # Signed boundary
    253, 254, 255,                    # Max values
]

WORD_BOUNDARIES = [
    0, 1, 2,
    62, 63, 64, 65, 66,
    126, 127, 128, 129, 130,
    253, 254, 255, 256, 257, 258,
    510, 511, 512, 513, 514,
    1022, 1023, 1024, 1025, 1026,
    2046, 2047, 2048, 2049, 2050,
    4094, 4095, 4096, 4097, 4098,
    8190, 8191, 8192, 8193, 8194,
    16382, 16383, 16384, 16385, 16386,
    32766, 32767, 32768, 32769, 32770,  # Signed boundary
    65533, 65534, 65535,               # Max values
]

DWORD_BOUNDARIES = [
    0, 1, 2,
    62, 63, 64, 65, 66,
    126, 127, 128, 129, 130,
    253, 254, 255, 256, 257, 258,
    510, 511, 512, 513, 514,
    1022, 1023, 1024, 1025, 1026,
    2046, 2047, 2048, 2049, 2050,
    4094, 4095, 4096, 4097, 4098,
    8190, 8191, 8192, 8193, 8194,
    16382, 16383, 16384, 16385, 16386,
    32766, 32767, 32768, 32769, 32770,
    65534, 65535, 65536, 65537, 65538,
    131070, 131071, 131072, 131073, 131074,
    262142, 262143, 262144, 262145, 262146,
    524286, 524287, 524288, 524289, 524290,
    1048574, 1048575, 1048576, 1048577, 1048578,
    2097150, 2097151, 2097152, 2097153, 2097154,
    4194302, 4194303, 4194304, 4194305, 4194306,
    8388606, 8388607, 8388608, 8388609, 8388610,
    16777214, 16777215, 16777216, 16777217, 16777218,
    33554430, 33554431, 33554432, 33554433, 33554434,
    67108862, 67108863, 67108864, 67108865, 67108866,
    134217726, 134217727, 134217728, 134217729, 134217730,
    268435454, 268435455, 268435456, 268435457, 268435458,
    536870910, 536870911, 536870912, 536870913, 536870914,
    1073741822, 1073741823, 1073741824, 1073741825, 1073741826,
    2147483646, 2147483647, 2147483648, 2147483649, 2147483650,  # Signed boundary
    4294967293, 4294967294, 4294967295,  # Max values
]

QWORD_BOUNDARIES = DWORD_BOUNDARIES + [
    4294967294, 4294967295, 4294967296, 4294967297, 4294967298,
    8589934590, 8589934591, 8589934592, 8589934593, 8589934594,
    # Key 64-bit boundaries
    0x7FFFFFFFFFFFFFFE, 0x7FFFFFFFFFFFFFFF,  # Signed max
    0x8000000000000000, 0x8000000000000001,  # Signed overflow
    0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,  # Max
]

# Signed boundaries (negative values)
SIGNED_BYTE_BOUNDARIES = [-128, -127, -1, 0, 1, 126, 127]
SIGNED_WORD_BOUNDARIES = [-32768, -32767, -1, 0, 1, 32766, 32767]
SIGNED_DWORD_BOUNDARIES = [-2147483648, -2147483647, -1, 0, 1, 2147483646, 2147483647]
SIGNED_QWORD_BOUNDARIES = [-9223372036854775808, -9223372036854775807, -1, 0, 1, 
                           9223372036854775806, 9223372036854775807]

# Array/count values
COUNT_VALUES = [
    0, 1, 2, 3, 4, 5,
    7, 8, 9,
    15, 16, 17,
    31, 32, 33,
    62, 63, 64, 65, 66,
    100, 127, 128, 129,
    200, 253, 254, 255, 256, 257,
    300, 400, 500, 511, 512, 513,
    552, 600, 700, 800, 900,
    1000, 1023, 1024, 1025,
    1500, 2000, 2047, 2048, 2049,
    3000, 4000, 4095, 4096, 4097,
    5000, 6000, 7000, 8000, 8191, 8192, 8193,
    10000, 12000, 16000, 16383, 16384, 16385,
    20000, 25000, 30000, 32000, 32767, 32768, 32769,
    40000, 50000, 60000, 65000, 65534, 65535,
]

# Length mismatch deltas
LENGTH_DELTAS = [
    -1000, -500, -256, -255, -128, -127, -100, -64, -63, -32, -31,
    -16, -15, -8, -7, -4, -3, -2, -1,
    1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    500, 1000, 2000, 4000, 8000, 16000, 32000, 65000,
]

# Offset corruption values
OFFSET_CORRUPTIONS = [
    0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
    -1, -2, -4, -8, -16, -32, -64, -128, -256,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,  # Large/negative interpretations
    0xDEADBEEF, 0xCAFEBABE, 0x41414141,  # Magic values
]

# VARINT boundaries (QUIC-style: 2-bit prefix determines length)
VARINT_BOUNDARIES = [
    0, 1,
    62, 63,                              # 1-byte max
    64, 65,                              # 2-byte min
    16382, 16383,                        # 2-byte max
    16384, 16385,                        # 4-byte min
    1073741822, 1073741823,              # 4-byte max
    1073741824, 1073741825,              # 8-byte min
    4611686018427387902, 4611686018427387903,  # 8-byte max
]

# Buffer overflow sizes
OVERFLOW_SIZES = [
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    100000, 500000, 1000000, 5000000, 10000000,
]

# Special byte patterns
SPECIAL_PATTERNS = {
    'null': b'\x00',
    'ones': b'\xff',
    'a_pattern': b'\x41',  # 'A'
    'format_string': b'%s%s%s%s%s%n%n%n%n',
    'sql_injection': b"' OR '1'='1",
    'path_traversal': b'..\\..\\..\\..\\',
    'unicode_overflow': b'\xef\xbb\xbf',  # BOM
    'null_unicode': b'\x00\x00',
}


# =============================================================================
# Mutation Data Classes
# =============================================================================

@dataclass
class Mutation:
    """Record of a single mutation applied to a field."""
    field: str                  # Field name (dotted path for nested)
    original: Any               # Original value
    fuzzed: Any                 # Fuzzed value
    strategy: str               # Strategy name used
    offset: int = 0             # Byte offset in packet (filled after serialization)
    size: int = 0               # Size in bytes


@dataclass
class ByteFlip:
    """Record of a byte-level flip."""
    offset: int
    original: int
    fuzzed: int


@dataclass
class FuzzInfo:
    """Complete information about fuzzing applied to a packet."""
    mode: FuzzMode
    mutations: List[Mutation] = field(default_factory=list)
    byteflips: List[ByteFlip] = field(default_factory=list)
    array_expansions: List[str] = field(default_factory=list)  # Structurally changed arrays
    length_mismatches: List[str] = field(default_factory=list)
    original_size: int = 0
    fuzzed_size: int = 0
    # Seed for this individual build. Passing it back to Framework.build(seed=...)
    # reproduces the same field selection and mutations.
    seed: Optional[int] = None


# =============================================================================
# Field Type Metadata
# =============================================================================

FIELD_TYPE_SIZES = {
    FieldType.BYTE: 1,
    FieldType.SBYTE: 1,
    FieldType.WORD: 2,
    FieldType.SWORD: 2,
    FieldType.WORD_BE: 2,
    FieldType.DWORD: 4,
    FieldType.SDWORD: 4,
    FieldType.DWORD_BE: 4,
    FieldType.QWORD: 8,
    FieldType.SQWORD: 8,
    FieldType.QWORD_BE: 8,
    FieldType.GUID: 16,
    FieldType.DER_NULL: 2,
    FieldType.DER_BOOLEAN: 3,
}

FIELD_TYPE_BOUNDARIES = {
    FieldType.BYTE: BYTE_BOUNDARIES,
    FieldType.SBYTE: SIGNED_BYTE_BOUNDARIES,
    FieldType.WORD: WORD_BOUNDARIES,
    FieldType.WORD_BE: WORD_BOUNDARIES,
    FieldType.SWORD: SIGNED_WORD_BOUNDARIES,
    FieldType.DWORD: DWORD_BOUNDARIES,
    FieldType.DWORD_BE: DWORD_BOUNDARIES,
    FieldType.SDWORD: SIGNED_DWORD_BOUNDARIES,
    FieldType.QWORD: QWORD_BOUNDARIES,
    FieldType.QWORD_BE: QWORD_BOUNDARIES,
    FieldType.SQWORD: SIGNED_QWORD_BOUNDARIES,
    FieldType.VARINT: VARINT_BOUNDARIES,
    FieldType.VARINT_SIGNED: SIGNED_QWORD_BOUNDARIES,
    FieldType.ULEB128: QWORD_BOUNDARIES,
    FieldType.SLEB128: SIGNED_QWORD_BOUNDARIES,
    FieldType.LENGTH: WORD_BOUNDARIES + DWORD_BOUNDARIES[:50],
    FieldType.COUNT: COUNT_VALUES,
    FieldType.OFFSET: DWORD_BOUNDARIES,
}

FIELD_TYPE_MAX = {
    FieldType.BYTE: 0xFF,
    FieldType.SBYTE: 127,
    FieldType.WORD: 0xFFFF,
    FieldType.WORD_BE: 0xFFFF,
    FieldType.SWORD: 32767,
    FieldType.DWORD: 0xFFFFFFFF,
    FieldType.DWORD_BE: 0xFFFFFFFF,
    FieldType.SDWORD: 2147483647,
    FieldType.QWORD: 0xFFFFFFFFFFFFFFFF,
    FieldType.QWORD_BE: 0xFFFFFFFFFFFFFFFF,
    FieldType.SQWORD: 9223372036854775807,
    FieldType.VARINT: 4611686018427387903,
    FieldType.VARINT_SIGNED: 9223372036854775807,
    FieldType.ULEB128: 0xFFFFFFFFFFFFFFFF,
    FieldType.SLEB128: 9223372036854775807,
}

FIELD_TYPE_MIN = {
    FieldType.BYTE: 0,
    FieldType.SBYTE: -128,
    FieldType.WORD: 0,
    FieldType.WORD_BE: 0,
    FieldType.SWORD: -32768,
    FieldType.DWORD: 0,
    FieldType.DWORD_BE: 0,
    FieldType.SDWORD: -2147483648,
    FieldType.QWORD: 0,
    FieldType.QWORD_BE: 0,
    FieldType.SQWORD: -9223372036854775808,
    FieldType.VARINT: 0,
    FieldType.VARINT_SIGNED: -9223372036854775808,
    FieldType.ULEB128: 0,
    FieldType.SLEB128: -9223372036854775808,
}


def get_boundaries(ftype: FieldType) -> List[int]:
    """Get boundary values for a field type."""
    return FIELD_TYPE_BOUNDARIES.get(ftype, DWORD_BOUNDARIES)


def get_random_boundary(ftype: FieldType, max_val: int = None, rng=None) -> int:
    """Get a random boundary value for a field type, optionally capped."""
    rng = rng if rng is not None else random
    boundaries = get_boundaries(ftype)
    if max_val is not None:
        boundaries = [b for b in boundaries if b <= max_val]
    if not boundaries:
        return 0
    return rng.choice(boundaries)


_INTEGER_BIT_WIDTHS = {
    FieldType.BYTE: 8,
    FieldType.SBYTE: 8,
    FieldType.WORD: 16,
    FieldType.SWORD: 16,
    FieldType.WORD_BE: 16,
    FieldType.DWORD: 32,
    FieldType.SDWORD: 32,
    FieldType.DWORD_BE: 32,
    FieldType.QWORD: 64,
    FieldType.SQWORD: 64,
    FieldType.QWORD_BE: 64,
    FieldType.VARINT: 62,
    FieldType.VARINT_SIGNED: 64,
    FieldType.ULEB128: 64,
    FieldType.SLEB128: 64,
    # Standalone helpers do not know a relation field's size_type. DWORD is
    # the framework default and matches the historical helper behaviour.
    FieldType.LENGTH: 32,
    FieldType.COUNT: 32,
    FieldType.OFFSET: 32,
}

_SIGNED_INTEGER_TYPES = {
    FieldType.SBYTE,
    FieldType.SWORD,
    FieldType.SDWORD,
    FieldType.SQWORD,
    FieldType.VARINT_SIGNED,
    FieldType.SLEB128,
}

_REPEATED_BYTES = [
    0x00, 0x01, 0x30, 0x41, 0x55, 0x7f, 0x80, 0xaa, 0xcc, 0xcd, 0xfe, 0xff,
]

_MAGIC_INTEGER_PATTERNS = [
    0xDEADBEEF,
    0xBAADF00D,
    0xCAFEBABE,
    0xFEEDFACE,
    0xC0DEC0DE,
    0x0BADC0DE,
    0xCCCCCCCC,
    0xCDCDCDCD,
    0xFEEEFEEE,
]

_ASCII_INTEGER_PATTERNS = [
    b'0000', b'1111', b'AAAA', b'aaaa', b'ABCD', b'abcd', b'    ', b'/./.',
]


def _integer_payload_families(ftype: FieldType, nominal: int) -> Dict[str, List[int]]:
    """Build type-safe structured integer payload families.

    The values are deliberately grouped by intent so mutation reports explain
    what was attempted.  Families are finite and deterministic; the separate
    ``random`` strategy in :func:`get_fuzz_integer` samples the entire numeric
    domain.
    """
    bit_width = _INTEGER_BIT_WIDTHS.get(ftype, 32)
    signed = ftype in _SIGNED_INTEGER_TYPES
    min_val = FIELD_TYPE_MIN.get(ftype, 0)
    max_val = FIELD_TYPE_MAX.get(ftype, 0xFFFFFFFF)
    mask = (1 << bit_width) - 1
    byte_width = (bit_width + 7) // 8
    nominal_bits = nominal & mask

    def fit_bits(value: int) -> int:
        """Interpret a bit pattern using this field's signedness and width."""
        value &= mask
        if signed and value & (1 << (bit_width - 1)):
            value -= 1 << bit_width
        return value

    def repeated_pattern(pattern: bytes) -> int:
        expanded = (pattern * ((byte_width + len(pattern) - 1) // len(pattern)))[:byte_width]
        return fit_bits(int.from_bytes(expanded, 'big'))

    families = {
        'boundary': list(get_boundaries(ftype)),
        # Sampling the small domain finds enum, index, allocation, loop and
        # state-machine bugs that sparse power-of-two boundaries can miss.
        'small_integer': list(range(max(min_val, -256), min(max_val, 255) + 1)),
        'zero': [0],
        'one': [1],
        'max': [max_val],
        'min': [min_val],
        'near_nominal': [
            nominal + delta for delta in LENGTH_DELTAS
            if min_val <= nominal + delta <= max_val
        ],
        'one_hot': [fit_bits(1 << bit) for bit in range(bit_width)],
        'one_cold': [fit_bits(mask ^ (1 << bit)) for bit in range(bit_width)],
        'nominal_bit_flip': [
            fit_bits(nominal_bits ^ (1 << bit)) for bit in range(bit_width)
        ],
        'bitwise_not': [fit_bits(~nominal_bits)],
        'repeated_byte': [
            repeated_pattern(bytes([byte])) for byte in _REPEATED_BYTES
        ],
        'alternating_bits': [
            repeated_pattern(b'\xaa'), repeated_pattern(b'\x55'),
        ],
        'magic': [fit_bits(value) for value in _MAGIC_INTEGER_PATTERNS],
        'ascii_pattern': [
            repeated_pattern(pattern) for pattern in _ASCII_INTEGER_PATTERNS
        ],
    }

    # Exercise truncation, partial-register use and sign/zero-extension at
    # every byte boundary below the field's native width.
    partial_width = []
    sign_extension = []
    for sub_width in range(8, bit_width, 8):
        low_mask = (1 << sub_width) - 1
        high_mask = mask ^ low_mask
        partial_width.extend([
            fit_bits(low_mask),
            fit_bits(high_mask),
            fit_bits(nominal_bits & low_mask),
            fit_bits(nominal_bits & high_mask),
        ])
        sign_extension.extend([
            fit_bits(mask ^ ((1 << (sub_width - 1)) - 1)),
            fit_bits(mask),
        ])
    families['partial_width'] = partial_width
    families['sign_extension'] = sign_extension

    if bit_width % 8 == 0 and byte_width > 1:
        swapped = int.from_bytes(
            nominal_bits.to_bytes(byte_width, 'little'), 'big'
        )
        families['byte_swap'] = [fit_bits(swapped)]

    # Remove duplicates inside each family, out-of-domain values, and the
    # nominal value: every reported structured mutation must change the field.
    cleaned = {}
    for name, values in families.items():
        unique = []
        seen = set()
        for value in values:
            if not min_val <= value <= max_val or value == nominal or value in seen:
                continue
            seen.add(value)
            unique.append(value)
        if unique:
            cleaned[name] = unique
    return cleaned


def get_fuzz_integer(ftype: FieldType, nominal: int = 0, rng=None,
                     strategy: str = None) -> Tuple[int, str]:
    """
    Get a fuzzed integer value and the strategy used.

    Args:
        ftype: Integer-compatible field type.
        nominal: Original field value.
        rng: Optional random.Random-compatible generator.
        strategy: Optional strategy name, primarily useful for deterministic
            testing or manual packet builders. By default a payload family is
            selected randomly.
    
    Returns:
        (fuzzed_value, strategy_name)
    """
    rng = rng if rng is not None else random
    max_val = FIELD_TYPE_MAX.get(ftype, 0xFFFFFFFF)
    min_val = FIELD_TYPE_MIN.get(ftype, 0)
    families = _integer_payload_families(ftype, nominal)
    available = list(families) + ['random']

    if strategy is not None and strategy not in available:
        choices = ', '.join(sorted(available))
        raise ValueError(f"unknown integer fuzz strategy {strategy!r}; choose from: {choices}")

    strategy_name = strategy if strategy is not None else rng.choice(available)
    if strategy_name != 'random':
        return rng.choice(families[strategy_name]), strategy_name

    # Random is intentionally uniform over the complete representable range,
    # rather than selecting from the curated payload corpus.
    value = nominal
    for _ in range(8):
        value = rng.randint(min_val, max_val)
        if value != nominal:
            return value, 'random'

    if min_val != max_val:
        return (min_val if nominal != min_val else max_val), 'alternate_boundary'
    return value, 'random'


def get_fuzz_buffer(size: int, strategy: str = None, rng=None) -> Tuple[bytes, str]:
    """
    Get a fuzzed buffer of approximately the given size.
    
    Returns:
        (buffer, strategy_name)
    """
    rng = rng if rng is not None else random
    if size < 0:
        raise ValueError("buffer size cannot be negative")
    if strategy is None:
        strategy = rng.choice(['overflow', 'null', 'pattern', 'random', 'truncate', 'empty'])
    
    if strategy == 'overflow':
        new_size = rng.choice([s for s in OVERFLOW_SIZES if s > size] or [max(1, size * 2)])
        return b'\x41' * new_size, 'overflow'
    elif strategy == 'null':
        return b'\x00' * size, 'null_fill'
    elif strategy == 'pattern':
        pattern = rng.choice(list(SPECIAL_PATTERNS.values()))
        return (pattern * ((size // len(pattern)) + 1))[:size], 'pattern'
    elif strategy == 'random':
        return bytes(rng.randint(0, 255) for _ in range(size)), 'random'
    elif strategy == 'truncate':
        new_size = max(0, size - rng.choice([1, 2, 4, 8, 16, 32, max(1, size // 2)]))
        return b'\x00' * new_size, 'truncate'
    elif strategy == 'empty':
        return b'', 'empty'
    else:
        return b'\x41' * size, 'default'

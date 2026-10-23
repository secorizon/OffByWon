"""
OffByWon Framework - DER/ASN.1 Serialization

Support for DER (Distinguished Encoding Rules) used in:
- X.509 certificates
- SPNEGO/GSS-API authentication
- LDAP
- Kerberos
- SMB authentication
"""

from typing import List, Any, Optional, Tuple
from .types import FieldType, get_fuzz_integer, get_fuzz_buffer, OVERFLOW_SIZES
import random


# =============================================================================
# DER Tag Classes
# =============================================================================

class DERTag:
    """DER tag constants."""
    # Class bits (bits 7-6)
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT = 0x80
    PRIVATE = 0xC0
    
    # Constructed bit (bit 5)
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x20
    
    # Universal tags
    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OID = 0x06
    ENUMERATED = 0x0A
    UTF8_STRING = 0x0C
    SEQUENCE = 0x10
    SET = 0x11
    PRINTABLE_STRING = 0x13
    IA5_STRING = 0x16
    UTC_TIME = 0x17
    GENERALIZED_TIME = 0x18


# =============================================================================
# DER Encoding Functions
# =============================================================================

def encode_der_length(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0:
        raise ValueError("DER length cannot be negative")
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    elif length < 65536:
        return bytes([0x82, length >> 8, length & 0xFF])
    elif length < 16777216:
        return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
    else:
        length_bytes = []
        temp = length
        while temp:
            length_bytes.append(temp & 0xFF)
            temp >>= 8
        length_bytes.reverse()
        return bytes([0x80 | len(length_bytes)] + length_bytes)


def fuzz_der_length(actual_length: int, rng=None) -> Tuple[bytes, str]:
    """
    Generate a fuzzed DER length encoding.
    
    Returns:
        (length_bytes, strategy_name)
    """
    rng = rng if rng is not None else random
    strategy = rng.choice([
        'correct', 'correct', 'correct',  # Weighted toward correct
        'short', 'long', 'zero', 'huge',
        'wrong_form', 'indefinite', 'invalid_multibyte'
    ])
    
    if strategy == 'correct':
        return encode_der_length(actual_length), 'correct'
    elif strategy == 'short':
        # Length says less than actual
        fuzzed = max(0, actual_length - rng.choice([1, 2, 4, 8, 16, 32, actual_length // 2]))
        return encode_der_length(fuzzed), 'length_short'
    elif strategy == 'long':
        # Length says more than actual
        fuzzed = actual_length + rng.choice([1, 2, 4, 8, 16, 32, 64, 128, 256, 1000])
        return encode_der_length(fuzzed), 'length_long'
    elif strategy == 'zero':
        return bytes([0x00]), 'length_zero'
    elif strategy == 'huge':
        return encode_der_length(rng.choice(OVERFLOW_SIZES)), 'length_huge'
    elif strategy == 'wrong_form':
        # Use long form when short would work
        if actual_length < 128:
            return bytes([0x81, actual_length]), 'unnecessary_long_form'
        return encode_der_length(actual_length), 'correct'
    elif strategy == 'indefinite':
        # Indefinite length (invalid for DER but some parsers accept)
        return bytes([0x80]), 'indefinite'
    elif strategy == 'invalid_multibyte':
        # Invalid multi-byte length (leading zeros)
        return bytes([0x82, 0x00, actual_length & 0xFF]), 'invalid_multibyte'
    
    return encode_der_length(actual_length), 'correct'


def encode_der_integer(value: int) -> bytes:
    """Encode an integer in DER format (minimal, signed)."""
    if not isinstance(value, int):
        raise TypeError("DER INTEGER value must be an int")
    if value == 0:
        return b'\x00'
    if value > 0:
        byte_len = max(1, (value.bit_length() + 7) // 8)
        encoded = value.to_bytes(byte_len, 'big')
        return b'\x00' + encoded if encoded[0] & 0x80 else encoded

    # Minimal signed two's-complement width. Exact negative powers of two (for
    # example -128 and -32768) must not receive a redundant leading 0xff.
    byte_len = max(1, ((~value).bit_length() + 8) // 8)
    return value.to_bytes(byte_len, 'big', signed=True)


def fuzz_der_integer(value: int, rng=None) -> Tuple[bytes, str]:
    """Generate a fuzzed DER INTEGER value."""
    rng = rng if rng is not None else random
    strategy = rng.choice([
        'correct', 'correct',
        'boundary', 'negative', 'huge', 'zero', 'leading_zeros', 'max_negative'
    ])
    
    if strategy == 'correct':
        return encode_der_integer(value), 'correct'
    elif strategy == 'boundary':
        fuzzed = rng.choice([
            127, 128, 255, 256, 32767, 32768, 65535, 65536,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
        ])
        return encode_der_integer(fuzzed), 'boundary'
    elif strategy == 'negative':
        fuzzed = rng.choice([-1, -128, -256, -32768, -65536, -2147483648])
        return encode_der_integer(fuzzed), 'negative'
    elif strategy == 'huge':
        # Very large integer
        fuzzed = rng.randint(0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        return encode_der_integer(fuzzed), 'huge'
    elif strategy == 'zero':
        return b'\x00', 'zero'
    elif strategy == 'leading_zeros':
        # Invalid: leading zeros
        encoded = encode_der_integer(value)
        return b'\x00\x00' + encoded, 'leading_zeros'
    elif strategy == 'max_negative':
        return encode_der_integer(-9223372036854775808), 'max_negative'
    
    return encode_der_integer(value), 'correct'


def encode_der_oid(oid: bytes) -> bytes:
    """Encode an OID value (just the value, no tag/length)."""
    return oid


def fuzz_der_oid(oid: bytes, rng=None) -> Tuple[bytes, str]:
    """Generate a fuzzed OID value."""
    rng = rng if rng is not None else random
    strategy = rng.choice([
        'correct', 'correct', 'correct',
        'garbage', 'empty', 'truncate', 'extend', 'invalid_encoding'
    ])
    
    if strategy == 'correct':
        return oid, 'correct'
    elif strategy == 'garbage':
        return bytes(rng.randint(0, 255) for _ in range(len(oid))), 'garbage'
    elif strategy == 'empty':
        return b'', 'empty'
    elif strategy == 'truncate':
        return oid[:len(oid)//2], 'truncate'
    elif strategy == 'extend':
        # Add extra bytes
        return oid + b'\x81\x00' * rng.randint(10, 100), 'extend'
    elif strategy == 'invalid_encoding':
        # Invalid high-bit encoding
        return b'\x80' * 50, 'invalid_encoding'
    
    return oid, 'correct'


def wrap_der(tag: int, content: bytes, fuzz: bool = False, rng=None) -> bytes:
    """
    Wrap content with DER tag and length.
    
    Args:
        tag: DER tag byte
        content: Content bytes
        fuzz: Whether to fuzz the length
    
    Returns:
        Complete TLV encoding
    """
    if fuzz:
        length_bytes, _ = fuzz_der_length(len(content), rng)
    else:
        length_bytes = encode_der_length(len(content))
    
    return bytes([tag]) + length_bytes + content


def encode_der_sequence(contents: List[bytes], fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER SEQUENCE."""
    content = b''.join(contents)
    return wrap_der(DERTag.SEQUENCE | DERTag.CONSTRUCTED, content, fuzz, rng)


def encode_der_set(contents: List[bytes], fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER SET."""
    if not fuzz:
        contents = sorted(contents)
    content = b''.join(contents)
    return wrap_der(DERTag.SET | DERTag.CONSTRUCTED, content, fuzz, rng)


def encode_der_octet_string(data: bytes, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER OCTET STRING."""
    return wrap_der(DERTag.OCTET_STRING, data, fuzz, rng)


def encode_der_bit_string(data: bytes, unused_bits: int = 0, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER BIT STRING."""
    if not 0 <= unused_bits <= 7:
        raise ValueError("unused_bits must be between 0 and 7")
    content = bytes([unused_bits]) + data
    return wrap_der(DERTag.BIT_STRING, content, fuzz, rng)


def encode_der_boolean(value: bool, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER BOOLEAN."""
    content = b'\xff' if value else b'\x00'
    return wrap_der(DERTag.BOOLEAN, content, fuzz, rng)


def encode_der_null() -> bytes:
    """Encode a DER NULL."""
    return bytes([DERTag.NULL, 0x00])


def encode_der_context(tag_num: int, content: bytes, implicit: bool = False, 
                       constructed: bool = True, fuzz: bool = False, rng=None) -> bytes:
    """
    Encode a context-specific tagged value.
    
    Args:
        tag_num: Tag number (0-30 for short form)
        content: Content bytes
        implicit: If True, use implicit tagging
        constructed: If True, content is constructed
        fuzz: Whether to fuzz the length
    """
    if not 0 <= tag_num <= 30:
        raise ValueError("short-form context tag number must be between 0 and 30")
    tag = DERTag.CONTEXT | tag_num
    # Implicit tagging replaces the tag number/class but retains whether the
    # underlying value is primitive or constructed.
    if constructed:
        tag |= DERTag.CONSTRUCTED
    return wrap_der(tag, content, fuzz, rng)


def encode_der_application(tag_num: int, content: bytes, constructed: bool = True,
                           fuzz: bool = False, rng=None) -> bytes:
    """Encode an application-specific tagged value."""
    if not 0 <= tag_num <= 30:
        raise ValueError("short-form application tag number must be between 0 and 30")
    tag = DERTag.APPLICATION | tag_num
    if constructed:
        tag |= DERTag.CONSTRUCTED
    return wrap_der(tag, content, fuzz, rng)


def encode_der_private(tag_num: int, content: bytes, constructed: bool = True,
                       fuzz: bool = False, rng=None) -> bytes:
    """Encode a private tagged value."""
    if not 0 <= tag_num <= 30:
        raise ValueError("short-form private tag number must be between 0 and 30")
    tag = DERTag.PRIVATE | tag_num
    if constructed:
        tag |= DERTag.CONSTRUCTED
    return wrap_der(tag, content, fuzz, rng)


def encode_der_string(value: str, string_type: FieldType, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER string type."""
    tag_map = {
        FieldType.DER_UTF8_STRING: (DERTag.UTF8_STRING, 'utf-8'),
        FieldType.DER_PRINTABLE_STRING: (DERTag.PRINTABLE_STRING, 'ascii'),
        FieldType.DER_IA5_STRING: (DERTag.IA5_STRING, 'ascii'),
    }
    
    tag, encoding = tag_map.get(string_type, (DERTag.UTF8_STRING, 'utf-8'))
    
    rng = rng if rng is not None else random
    if fuzz:
        strategy = rng.choice(['correct', 'overflow', 'invalid_chars', 'wrong_encoding'])
        if strategy == 'overflow':
            value = value + 'A' * rng.choice([100, 1000, 10000])
        elif strategy == 'invalid_chars':
            value = value + '\x00\x01\x02'  # Control characters
        elif strategy == 'wrong_encoding':
            # Try to encode UTF-8 content as ASCII (may fail)
            try:
                content = value.encode('utf-8')  # Force UTF-8
            except UnicodeError:
                content = value.encode(encoding, errors='replace')
            return wrap_der(tag, content, True, rng)
    
    content = value.encode(encoding, errors='replace')
    return wrap_der(tag, content, fuzz, rng)


def encode_der_time(value: str, time_type: FieldType, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER time type (UTC or Generalized)."""
    if time_type == FieldType.DER_UTC_TIME:
        tag = DERTag.UTC_TIME
    else:
        tag = DERTag.GENERALIZED_TIME
    
    rng = rng if rng is not None else random
    if fuzz:
        strategy = rng.choice(['correct', 'invalid_format', 'future', 'past', 'garbage'])
        if strategy == 'invalid_format':
            value = 'AAAAAAAAAAAAAAAA'
        elif strategy == 'future':
            value = '99991231235959Z'
        elif strategy == 'past':
            value = '00000101000000Z'
        elif strategy == 'garbage':
            value = bytes(rng.randint(0, 255) for _ in range(16)).decode('latin-1')
    
    return wrap_der(tag, value.encode('ascii', errors='replace'), fuzz, rng)


def encode_der_enumerated(value: int, fuzz: bool = False, rng=None) -> bytes:
    """Encode a DER ENUMERATED value."""
    if fuzz:
        content, _ = fuzz_der_integer(value, rng)
    else:
        content = encode_der_integer(value)
    return wrap_der(DERTag.ENUMERATED, content, fuzz, rng)


# =============================================================================
# DER Fuzzing Strategies
# =============================================================================

class DERFuzzer:
    """Collection of DER-specific fuzzing strategies."""
    
    @staticmethod
    def fuzz_tag(tag: int, rng=None) -> Tuple[int, str]:
        """Fuzz a DER tag byte."""
        rng = rng if rng is not None else random
        strategy = rng.choice([
            'correct', 'correct', 'correct',
            'flip_class', 'flip_constructed', 'wrong_universal', 'invalid'
        ])
        
        if strategy == 'correct':
            return tag, 'correct'
        elif strategy == 'flip_class':
            # Flip between universal/context/application/private
            new_class = rng.choice([0x00, 0x40, 0x80, 0xC0])
            return (tag & 0x3F) | new_class, 'flip_class'
        elif strategy == 'flip_constructed':
            return tag ^ 0x20, 'flip_constructed'
        elif strategy == 'wrong_universal':
            # Use wrong universal tag
            return rng.choice([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x11]), 'wrong_universal'
        elif strategy == 'invalid':
            return rng.randint(0, 255), 'invalid_tag'
        
        return tag, 'correct'
    
    @staticmethod
    def fuzz_structure(children: List[bytes], rng=None) -> Tuple[List[bytes], str]:
        """Fuzz a DER structure (SEQUENCE, SET, etc.)."""
        rng = rng if rng is not None else random
        strategy = rng.choice([
            'correct', 'correct', 'correct',
            'reorder', 'duplicate', 'remove', 'add_garbage', 'truncate'
        ])
        
        if strategy == 'correct' or len(children) == 0:
            return children, 'correct'
        elif strategy == 'reorder':
            result = children.copy()
            rng.shuffle(result)
            return result, 'reorder'
        elif strategy == 'duplicate':
            idx = rng.randint(0, len(children) - 1)
            result = children.copy()
            result.insert(idx, children[idx])
            return result, 'duplicate'
        elif strategy == 'remove':
            idx = rng.randint(0, len(children) - 1)
            result = children.copy()
            result.pop(idx)
            return result, 'remove'
        elif strategy == 'add_garbage':
            garbage = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 100)))
            result = children.copy()
            result.append(garbage)
            return result, 'add_garbage'
        elif strategy == 'truncate':
            return children[:len(children)//2], 'truncate'
        
        return children, 'correct'
    
    @staticmethod
    def get_overflow_content(original_size: int, rng=None) -> bytes:
        """Generate overflow content for DER fuzzing."""
        rng = rng if rng is not None else random
        new_size = rng.choice([s for s in OVERFLOW_SIZES if s > original_size] or [max(1, original_size * 2)])
        pattern = rng.choice([b'\x00', b'\x41', b'\xff'])
        return pattern * new_size


# =============================================================================
# SPNEGO/GSS-API Helpers
# =============================================================================

def build_spnego_init(mech_types: List[bytes], mech_token: bytes,
                      fuzz: bool = False, rng=None) -> bytes:
    """
    Build a SPNEGO NegTokenInit message.
    
    Args:
        mech_types: List of mechanism OID bytes
        mech_token: Mechanism token (e.g., NTLM Type 1)
        fuzz: Whether to apply fuzzing
    """
    # MechTypeList ::= SEQUENCE OF MechType
    mech_oids = []
    for oid in mech_types:
        mech_oids.append(wrap_der(DERTag.OID, oid, fuzz, rng))
    mech_list = encode_der_sequence(mech_oids, fuzz, rng)
    
    # mechTypes [0] MechTypeList
    mech_types_tagged = encode_der_context(0, mech_list, fuzz=fuzz, rng=rng)
    
    # mechToken [2] OCTET STRING OPTIONAL
    token_inner = encode_der_octet_string(mech_token, fuzz, rng)
    token_tagged = encode_der_context(2, token_inner, fuzz=fuzz, rng=rng)
    
    # NegTokenInit ::= SEQUENCE
    nego_init = encode_der_sequence([mech_types_tagged, token_tagged], fuzz, rng)
    
    # NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit }
    nego_token = encode_der_context(0, nego_init, fuzz=fuzz, rng=rng)
    
    # GSS-API wrapper: InitialContextToken
    # thisMech OBJECT IDENTIFIER (SPNEGO)
    spnego_oid = wrap_der(DERTag.OID, OID_SPNEGO_RAW, fuzz, rng)
    inner = spnego_oid + nego_token
    
    # APPLICATION[0] constructed
    return encode_der_application(0, inner, fuzz=fuzz, rng=rng)


def build_spnego_response(mech_token: bytes, fuzz: bool = False, rng=None) -> bytes:
    """
    Build a SPNEGO NegTokenResp message.
    
    Args:
        mech_token: Mechanism token (e.g., NTLM Type 3)
        fuzz: Whether to apply fuzzing
    """
    # responseToken [2] OCTET STRING OPTIONAL
    token_inner = encode_der_octet_string(mech_token, fuzz, rng)
    token_tagged = encode_der_context(2, token_inner, fuzz=fuzz, rng=rng)
    
    # NegTokenResp ::= SEQUENCE
    nego_resp = encode_der_sequence([token_tagged], fuzz, rng)
    
    # NegotiationToken ::= CHOICE { negTokenResp [1] NegTokenResp }
    return encode_der_context(1, nego_resp, fuzz=fuzz, rng=rng)


# Raw OID bytes (without tag/length)
OID_SPNEGO_RAW = bytes([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])  # 1.3.6.1.5.5.2
OID_NTLM_RAW = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
OID_KERBEROS_RAW = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02])
OID_NEGOEX_RAW = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e])


# =============================================================================
# LDAP Helpers
# =============================================================================

def build_ldap_message(message_id: int, request: bytes, controls: bytes = None,
                       fuzz: bool = False, rng=None) -> bytes:
    """
    Build an LDAP message envelope.
    
    Args:
        message_id: LDAP message ID
        request: Protocol operation (BindRequest, SearchRequest, etc.)
        controls: Optional controls
        fuzz: Whether to apply fuzzing
    """
    # MessageID ::= INTEGER
    msg_id = wrap_der(DERTag.INTEGER, encode_der_integer(message_id), fuzz, rng)
    
    components = [msg_id, request]
    
    if controls is not None:
        # Controls ::= SEQUENCE OF Control
        controls_tagged = encode_der_context(0, controls, fuzz=fuzz, rng=rng)
        components.append(controls_tagged)
    
    # LDAPMessage ::= SEQUENCE
    return encode_der_sequence(components, fuzz, rng)


def build_ldap_bind_request(version: int, name: bytes, auth: bytes,
                            fuzz: bool = False, rng=None) -> bytes:
    """
    Build an LDAP BindRequest.
    
    Args:
        version: LDAP version (usually 3)
        name: DN to bind as
        auth: Authentication data
        fuzz: Whether to apply fuzzing
    """
    # version INTEGER
    ver = wrap_der(DERTag.INTEGER, encode_der_integer(version), fuzz, rng)
    
    # name LDAPDN (OCTET STRING)
    dn = encode_der_octet_string(name, fuzz, rng)
    
    # BindRequest ::= [APPLICATION 0] SEQUENCE
    # BindRequest is an implicitly tagged SEQUENCE. Build its content octets
    # directly; slicing ``inner[2:]`` corrupts messages whose length header is
    # longer than one byte.
    content = b''.join([ver, dn, auth])
    return encode_der_application(0, content, fuzz=fuzz, rng=rng)


def build_ldap_sasl_auth(mechanism: bytes, credentials: bytes = None,
                         fuzz: bool = False, rng=None) -> bytes:
    """
    Build LDAP SASL authentication.
    
    Args:
        mechanism: SASL mechanism name
        credentials: Optional SASL credentials
        fuzz: Whether to apply fuzzing
    """
    # mechanism OCTET STRING
    mech = encode_der_octet_string(mechanism, fuzz, rng)
    
    components = [mech]
    
    if credentials is not None:
        # credentials OCTET STRING OPTIONAL
        creds = encode_der_octet_string(credentials, fuzz, rng)
        components.append(creds)
    
    # [3] SaslCredentials is an implicitly tagged constructed SEQUENCE, so its
    # value is the concatenation of member TLVs, not a nested SEQUENCE TLV.
    content = b''.join(components)
    return encode_der_context(
        3, content, implicit=True, constructed=True, fuzz=fuzz, rng=rng,
    )

"""
OffByWon Framework - Declarative Protocol Fuzzing

A framework for building and fuzzing network protocol packets using
declarative field definitions.

Quick Start:
    from offbywon import Framework, Packet, Field, FieldType
    
    class MyPacket(Packet):
        fields = [
            Field('version', FieldType.BYTE, 1),
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.WORD),
            Field('data', FieldType.BYTES),
        ]
    
    fw = Framework()
    data, info = fw.build(MyPacket, mode='combined', values={'data': b'hello'})
    
Features:
    - Declarative packet definitions with Field types
    - Automatic length/count/offset resolution
    - Multiple fuzzing modes (field, blind, byteflip, combined, length, array, full)
    - DER/ASN.1 support for authentication protocols
    - Type-specific boundary value sets and structured integer mutations
    - Standardized output formatting
    - A limited migration shim for three manual-building helpers from v1

See the individual module docstrings for detailed documentation.
"""

__version__ = '2.0.0'
__author__ = 'Laurent Gaffié'

# Core types
from .types import (
    FieldType,
    FuzzMode,
    Mutation,
    ByteFlip,
    FuzzInfo,
    # Boundary values for custom fuzzing
    BYTE_BOUNDARIES,
    WORD_BOUNDARIES,
    DWORD_BOUNDARIES,
    QWORD_BOUNDARIES,
    COUNT_VALUES,
    LENGTH_DELTAS,
    OFFSET_CORRUPTIONS,
    OVERFLOW_SIZES,
    VARINT_BOUNDARIES,
    # Helper functions
    get_fuzz_integer,
    get_fuzz_buffer,
    get_boundaries,
    get_random_boundary,
)

# Packet definitions
from .packet import (
    Field,
    Marker,
    Packet,
)

# Framework
from .framework import (
    Framework,
    ProtocolFuzzer,  # Limited v1 migration shim
    get_fuzz_value,
    get_fuzz_size,
    fuzz_buffer,
)

# DER/ASN.1 helpers
from .der import (
    DERTag,
    encode_der_length,
    encode_der_integer,
    encode_der_oid,
    encode_der_sequence,
    encode_der_set,
    encode_der_octet_string,
    encode_der_bit_string,
    encode_der_boolean,
    encode_der_null,
    encode_der_context,
    encode_der_application,
    encode_der_private,
    encode_der_string,
    encode_der_time,
    encode_der_enumerated,
    fuzz_der_length,
    fuzz_der_integer,
    fuzz_der_oid,
    wrap_der,
    build_spnego_init,
    build_spnego_response,
    build_ldap_message,
    build_ldap_bind_request,
    build_ldap_sasl_auth,
    DERFuzzer,
    OID_SPNEGO_RAW,
    OID_NTLM_RAW,
    OID_KERBEROS_RAW,
    OID_NEGOEX_RAW,
)

# Serializer (for advanced use)
from .serializer import (
    Serializer,
    SerializerContext,
)

__all__ = [
    # Version
    '__version__',
    
    # Core types
    'FieldType',
    'FuzzMode',
    'Mutation',
    'ByteFlip',
    'FuzzInfo',
    
    # Boundary values
    'BYTE_BOUNDARIES',
    'WORD_BOUNDARIES',
    'DWORD_BOUNDARIES',
    'QWORD_BOUNDARIES',
    'COUNT_VALUES',
    'LENGTH_DELTAS',
    'OFFSET_CORRUPTIONS',
    'OVERFLOW_SIZES',
    'VARINT_BOUNDARIES',
    
    # Helper functions
    'get_fuzz_integer',
    'get_fuzz_buffer',
    'get_boundaries',
    'get_random_boundary',
    'get_fuzz_value',
    'get_fuzz_size',
    'fuzz_buffer',
    
    # Packet definitions
    'Field',
    'Marker',
    'Packet',
    
    # OID constants (raw bytes for protocol implementations)
    'OID_SPNEGO_RAW',
    'OID_NTLM_RAW',
    'OID_KERBEROS_RAW',
    'OID_NEGOEX_RAW',
    
    # Framework
    'Framework',
    'ProtocolFuzzer',
    
    # DER/ASN.1
    'DERTag',
    'encode_der_length',
    'encode_der_integer',
    'encode_der_oid',
    'encode_der_sequence',
    'encode_der_set',
    'encode_der_octet_string',
    'encode_der_bit_string',
    'encode_der_boolean',
    'encode_der_null',
    'encode_der_context',
    'encode_der_application',
    'encode_der_private',
    'encode_der_string',
    'encode_der_time',
    'encode_der_enumerated',
    'fuzz_der_length',
    'fuzz_der_integer',
    'fuzz_der_oid',
    'wrap_der',
    'build_spnego_init',
    'build_spnego_response',
    'build_ldap_message',
    'build_ldap_bind_request',
    'build_ldap_sasl_auth',
    'DERFuzzer',
    
    # Serializer
    'Serializer',
    'SerializerContext',
]

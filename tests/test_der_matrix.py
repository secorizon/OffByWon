"""DER helper and declarative DER serialization coverage."""

import random

import pytest

from offbywon import (
    DERFuzzer,
    DERTag,
    Field,
    FieldType,
    Framework,
    Packet,
    build_ldap_message,
    build_spnego_response,
    encode_der_application,
    encode_der_bit_string,
    encode_der_boolean,
    encode_der_context,
    encode_der_enumerated,
    encode_der_integer,
    encode_der_length,
    encode_der_null,
    encode_der_octet_string,
    encode_der_private,
    encode_der_sequence,
    encode_der_set,
    encode_der_string,
    encode_der_time,
    fuzz_der_integer,
    fuzz_der_length,
    fuzz_der_oid,
    wrap_der,
)


class StrategyRNG:
    """Choose one named strategy, then deterministic values within it."""

    def __init__(self, strategy):
        self.strategy = strategy
        self.used_strategy = False

    def choice(self, values):
        if not self.used_strategy and self.strategy in values:
            self.used_strategy = True
            return self.strategy
        return values[0]

    def randint(self, low, high):
        return low

    def shuffle(self, values):
        values.reverse()


@pytest.mark.parametrize('length,expected', [
    (0, b'\x00'),
    (127, b'\x7f'),
    (128, b'\x81\x80'),
    (255, b'\x81\xff'),
    (256, b'\x82\x01\x00'),
    (65536, b'\x83\x01\x00\x00'),
    (1 << 24, b'\x84\x01\x00\x00\x00'),
])
def test_der_length_forms(length, expected):
    assert encode_der_length(length) == expected


def test_der_length_rejects_negative_values():
    with pytest.raises(ValueError):
        encode_der_length(-1)


@pytest.mark.parametrize('value,expected', [
    (0, b'\x00'),
    (127, b'\x7f'),
    (128, b'\x00\x80'),
    (255, b'\x00\xff'),
    (-1, b'\xff'),
    (-128, b'\x80'),
    (-129, b'\xff\x7f'),
])
def test_der_integer_sign_and_minimal_width(value, expected):
    assert encode_der_integer(value) == expected


def test_clean_der_helpers_emit_expected_tags_and_content():
    integer = wrap_der(DERTag.INTEGER, encode_der_integer(1))
    octets = encode_der_octet_string(b'A')
    assert encode_der_sequence([integer, octets]) == b'\x30\x06\x02\x01\x01\x04\x01A'
    assert encode_der_set([octets, integer]) == b'\x31\x06\x02\x01\x01\x04\x01A'
    assert encode_der_bit_string(b'\x80', 7) == b'\x03\x02\x07\x80'
    assert encode_der_boolean(True) == b'\x01\x01\xff'
    assert encode_der_boolean(False) == b'\x01\x01\x00'
    assert encode_der_null() == b'\x05\x00'
    assert encode_der_context(2, b'x', constructed=False) == b'\x82\x01x'
    assert encode_der_application(1, b'x', constructed=False) == b'\x41\x01x'
    assert encode_der_private(1, b'x', constructed=False) == b'\xc1\x01x'
    assert encode_der_enumerated(2) == b'\x0a\x01\x02'
    assert encode_der_string('é', FieldType.DER_UTF8_STRING) == b'\x0c\x02\xc3\xa9'
    assert encode_der_string('A', FieldType.DER_PRINTABLE_STRING) == b'\x13\x01A'
    assert encode_der_string('A', FieldType.DER_IA5_STRING) == b'\x16\x01A'
    assert encode_der_time('250101000000Z', FieldType.DER_UTC_TIME).startswith(b'\x17')
    assert encode_der_time('20250101000000Z', FieldType.DER_GENERALIZED_TIME).startswith(b'\x18')


def test_der_helper_input_validation():
    with pytest.raises(ValueError, match='unused_bits'):
        encode_der_bit_string(b'', 8)
    with pytest.raises(ValueError, match='tag number'):
        encode_der_context(31, b'')
    with pytest.raises(ValueError, match='tag number'):
        encode_der_application(-1, b'')
    with pytest.raises(ValueError, match='tag number'):
        encode_der_private(40, b'')
    with pytest.raises(TypeError):
        encode_der_integer('1')


@pytest.mark.parametrize('strategy', [
    'correct', 'short', 'long', 'zero', 'huge', 'wrong_form',
    'indefinite', 'invalid_multibyte',
])
def test_every_der_length_fuzz_strategy(strategy):
    encoded, reported = fuzz_der_length(12, StrategyRNG(strategy))
    assert isinstance(encoded, bytes) and encoded
    assert isinstance(reported, str)


@pytest.mark.parametrize('strategy', [
    'correct', 'boundary', 'negative', 'huge', 'zero',
    'leading_zeros', 'max_negative',
])
def test_every_der_integer_fuzz_strategy(strategy):
    encoded, reported = fuzz_der_integer(12, StrategyRNG(strategy))
    assert isinstance(encoded, bytes) and encoded
    assert isinstance(reported, str)


@pytest.mark.parametrize('strategy', [
    'correct', 'garbage', 'empty', 'truncate', 'extend', 'invalid_encoding',
])
def test_every_der_oid_fuzz_strategy(strategy):
    encoded, reported = fuzz_der_oid(b'\x2a\x03\x04', StrategyRNG(strategy))
    assert isinstance(encoded, bytes)
    assert isinstance(reported, str)


@pytest.mark.parametrize('strategy', [
    'correct', 'flip_class', 'flip_constructed', 'wrong_universal', 'invalid',
])
def test_every_der_tag_fuzz_strategy(strategy):
    tag, reported = DERFuzzer.fuzz_tag(0x30, StrategyRNG(strategy))
    assert 0 <= tag <= 255
    assert isinstance(reported, str)


@pytest.mark.parametrize('strategy,expected_size', [
    ('correct', 2),
    ('reorder', 2),
    ('duplicate', 3),
    ('remove', 1),
    ('add_garbage', 3),
    ('truncate', 1),
])
def test_every_der_structure_fuzz_strategy(strategy, expected_size):
    children, reported = DERFuzzer.fuzz_structure(
        [b'first', b'second'], StrategyRNG(strategy),
    )
    assert len(children) == expected_size
    assert isinstance(reported, str)


def test_der_overflow_content_uses_requested_larger_boundary():
    content = DERFuzzer.get_overflow_content(100, random.Random(1))
    assert len(content) > 100


def test_declarative_der_matrix_and_mutation():
    class DERPacket(Packet):
        fields = [
            Field('integer', FieldType.DER_INTEGER, -128, fuzz=False),
            Field('octets', FieldType.DER_OCTET_STRING, b'ab', fuzz=False),
            Field('bits', FieldType.DER_BIT_STRING, b'\x80', fuzz=False),
            Field('oid', FieldType.DER_OID, b'\x2a\x03', fuzz=False),
            Field('boolean', FieldType.DER_BOOLEAN, True, fuzz=False),
            Field('null', FieldType.DER_NULL, fuzz=False),
            Field('enum', FieldType.DER_ENUMERATED, 2, fuzz=False),
            Field('utf8', FieldType.DER_UTF8_STRING, 'x', fuzz=False),
            Field('printable', FieldType.DER_PRINTABLE_STRING, 'x', fuzz=False),
            Field('ia5', FieldType.DER_IA5_STRING, 'x', fuzz=False),
            Field('utc', FieldType.DER_UTC_TIME, '250101000000Z', fuzz=False),
            Field('generalized', FieldType.DER_GENERALIZED_TIME,
                  '20250101000000Z', fuzz=False),
            Field('context', FieldType.DER_CONTEXT, b'x', tag=1,
                  constructed=False, fuzz=False),
            Field('application', FieldType.DER_APPLICATION, b'x', tag=1,
                  constructed=False, fuzz=False),
            Field('private', FieldType.DER_PRIVATE, b'x', tag=1,
                  constructed=False, fuzz=False),
            Field('any', FieldType.DER_ANY, b'\x05\x00', fuzz=False),
        ]

    clean = Framework(verbose=False).build_clean(DERPacket)
    assert clean.startswith(b'\x02\x01\x80\x04\x02ab')
    assert clean.endswith(b'\x05\x00')

    class FuzzedDER(Packet):
        fields = [Field('value', FieldType.DER_SEQUENCE, {}, children=[
            Field('number', FieldType.DER_INTEGER, 1),
            Field('data', FieldType.DER_OCTET_STRING, b'x'),
        ])]

    fuzzed, info = Framework(verbose=False).build(
        FuzzedDER, mode='field', fields=['value'], seed=123,
    )
    assert info.mutations and info.mutations[0].strategy == 'der_mutation'
    assert fuzzed != Framework(verbose=False).build_clean(FuzzedDER)


def test_implicit_declarative_tag_strips_long_form_child_header():
    class Implicit(Packet):
        fields = [Field('tagged', FieldType.DER_CONTEXT, {}, tag=3,
                        implicit=True, constructed=True, children=[
            Field('sequence', FieldType.DER_SEQUENCE, {}, children=[
                Field('data', FieldType.DER_OCTET_STRING, b'A' * 200),
            ]),
        ], fuzz=False)]

    encoded = Framework(verbose=False).build_clean(Implicit)
    assert encoded[0] == 0xa3
    width = encoded[1] & 0x7f
    content_offset = 2 + width
    assert encoded[content_offset] == DERTag.OCTET_STRING


def test_protocol_der_helpers_accept_empty_optionals_and_rng():
    sasl_response = build_spnego_response(b'token', rng=random.Random(1))
    assert sasl_response[0] == 0xa1
    ldap = build_ldap_message(1, b'\x60\x00', controls=b'', rng=random.Random(1))
    assert ldap[0] == 0x30

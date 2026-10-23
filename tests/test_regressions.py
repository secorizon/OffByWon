"""Regression coverage for correctness and reproducibility fixes."""

import struct
import random

import pytest

from offbywon import (
    Field,
    FieldType,
    Framework,
    Packet,
    build_ldap_bind_request,
    build_ldap_sasl_auth,
    encode_der_context,
    encode_der_integer,
    get_fuzz_integer,
)


def test_count_fixup_uses_actual_array_count():
    class CountPacket(Packet):
        fields = [
            Field('count', FieldType.COUNT, target='items', size_type=FieldType.WORD),
            Field('items', FieldType.ARRAY, element=FieldType.DWORD, element_size=4),
        ]

    data = Framework(verbose=False).build_clean(CountPacket, {'items': [1, 2, 3]})
    assert data[:2] == b'\x03\x00'


def test_nested_fixups_are_scoped_to_each_structure():
    class Inner(Packet):
        fields = [
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.BYTE),
            Field('data', FieldType.BYTES),
        ]

    class Outer(Packet):
        fields = [
            Field('first', FieldType.STRUCT, element=Inner),
            Field('second', FieldType.STRUCT, element=Inner),
        ]

    data = Framework(verbose=False).build_clean(Outer, {
        'first': {'data': b'A'},
        'second': {'data': b'BBBB'},
    })
    assert data == b'\x01A\x04BBBB'


def test_dotted_values_instantiate_nested_packets():
    class Inner(Packet):
        fields = [Field('value', FieldType.BYTE, 1)]

    class Outer(Packet):
        fields = [Field('inner', FieldType.STRUCT, element=Inner)]

    assert Framework(verbose=False).build_clean(Outer, {'inner.value': 9}) == b'\x09'


def test_nested_field_collection_and_targeting():
    class Inner(Packet):
        fields = [Field('value', FieldType.DWORD, 7)]

    class Outer(Packet):
        fields = [Field('inner', FieldType.STRUCT, element=Inner)]

    _, info = Framework(verbose=False).build(
        Outer, mode='field', fields=['inner.value'], seed=8,
    )
    assert [mutation.field for mutation in info.mutations] == ['inner.value']


def test_size_from_and_count_from_are_enforced():
    class Sized(Packet):
        fields = [
            Field('size', FieldType.BYTE, 2, fuzz=False),
            Field('data', FieldType.BYTES, b'abcd', size_from='size', fuzz=False),
        ]

    class Counted(Packet):
        fields = [
            Field('count', FieldType.BYTE, 3, fuzz=False),
            Field('items', FieldType.ARRAY, [9], element=FieldType.BYTE,
                  element_size=1, count_from='count', fuzz=False),
        ]

    fw = Framework(verbose=False)
    assert fw.build_clean(Sized) == b'\x02ab'
    assert fw.build_clean(Counted) == b'\x03\x09\x09\x09'


@pytest.mark.parametrize('value, expected', [
    (0, b'\x00'),
    (-1, b'\x01'),
    (1, b'\x02'),
    (-2, b'\x03'),
])
def test_signed_varint_uses_zigzag(value, expected):
    class Signed(Packet):
        fields = [Field('value', FieldType.VARINT_SIGNED, 0)]

    assert Framework(verbose=False).build_clean(Signed, {'value': value}) == expected


def test_discriminated_union_selects_wire_type():
    class UnionPacket(Packet):
        fields = [
            Field('kind', FieldType.BYTE, 1, fuzz=False),
            Field('payload', FieldType.UNION, 0x1234,
                  selector='kind', choices={1: FieldType.WORD, 2: FieldType.DWORD}),
        ]

    assert Framework(verbose=False).build_clean(UnionPacket) == b'\x01\x34\x12'


def test_all_ndr_array_header_forms_are_serialized():
    class Conformant(Packet):
        fields = [Field('items', FieldType.NDR_CONFORMANT, [1, 2],
                        element=FieldType.DWORD)]

    class Varying(Packet):
        fields = [Field('items', FieldType.NDR_VARYING, [1, 2],
                        element=FieldType.DWORD, ndr_offset=1)]

    class Both(Packet):
        fields = [Field('items', FieldType.NDR_CONFORMANT_VARYING, [1, 2],
                        element=FieldType.DWORD, ndr_offset=1)]

    fw = Framework(verbose=False)
    assert fw.build_clean(Conformant) == struct.pack('<III', 2, 1, 2)
    assert fw.build_clean(Varying) == struct.pack('<IIII', 1, 2, 1, 2)
    assert fw.build_clean(Both) == struct.pack('<IIIII', 3, 1, 2, 1, 2)


def test_der_negative_integer_is_minimal():
    assert encode_der_integer(-128) == b'\x80'
    assert encode_der_integer(-32768) == b'\x80\x00'
    assert encode_der_integer(-129) == b'\xff\x7f'


def test_constructed_implicit_context_tag_and_large_ldap_body():
    assert encode_der_context(3, b'body', implicit=True, constructed=True)[0] == 0xa3
    assert build_ldap_sasl_auth(b'NTLM', b'x')[0] == 0xa3

    bind = build_ldap_bind_request(3, b'A' * 200, b'\x80\x00')
    assert bind[0] == 0x60
    width = bind[1] & 0x7f
    content_offset = 2 + width if bind[1] & 0x80 else 2
    assert bind[content_offset] == 0x02  # version INTEGER, not a sliced length octet


def test_optional_der_child_is_omitted():
    class OptionalDER(Packet):
        fields = [Field(
            'sequence', FieldType.DER_SEQUENCE, {}, children=[
                Field('optional', FieldType.DER_INTEGER, optional=True),
            ], fuzz=False,
        )]

    assert Framework(verbose=False).build_clean(OptionalDER) == b'\x30\x00'


def test_field_and_length_modes_mutate_only_eligible_fields():
    class LengthPacket(Packet):
        fields = [
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.WORD),
            Field('data', FieldType.BYTES, b'payload'),
        ]

    fw = Framework(verbose=False)
    data, info = fw.build(LengthPacket, mode='field', fields=['length'], seed=5)
    assert info.mutations and info.mutations[0].field == 'length'
    assert data[2:] == b'payload'
    assert int.from_bytes(data[:2], 'little') != len(data[2:])

    data, info = fw.build(LengthPacket, mode='length', seed=6)
    assert info.mutations and {mutation.field for mutation in info.mutations} == {'length'}
    assert data[2:] == b'payload'
    with pytest.raises(ValueError, match='ineligible'):
        fw.build(LengthPacket, mode='length', fields=['data'], seed=6)


def test_default_field_mode_always_selects_a_mutation():
    class Scalar(Packet):
        fields = [Field('value', FieldType.DWORD, 42)]

    clean = Framework(verbose=False).build_clean(Scalar)
    for seed in range(20):
        data, info = Framework(verbose=False).build(Scalar, mode='field', seed=seed)
        assert info.mutations
        assert data != clean


def test_structured_integer_payload_families():
    nominal = 0xDEADBEEF

    value, strategy = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(1), strategy='byte_swap',
    )
    assert (value, strategy) == (0xEFBEADDE, 'byte_swap')

    value, strategy = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(1), strategy='bitwise_not',
    )
    assert (value, strategy) == (0x21524110, 'bitwise_not')

    value, _ = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(2), strategy='small_integer',
    )
    assert 0 <= value <= 255

    value, _ = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(3), strategy='one_hot',
    )
    assert value != 0 and value & (value - 1) == 0

    value, _ = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(4), strategy='one_cold',
    )
    assert ((~value) & 0xffffffff).bit_count() == 1

    value, _ = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(5), strategy='nominal_bit_flip',
    )
    assert (value ^ nominal).bit_count() == 1

    value, _ = get_fuzz_integer(
        FieldType.DWORD, nominal, random.Random(6), strategy='repeated_byte',
    )
    encoded = value.to_bytes(4, 'big')
    assert len(set(encoded)) == 1


def test_structured_integer_payloads_reach_framework_fields():
    class Scalar(Packet):
        fields = [Field('value', FieldType.DWORD, 0xDEADBEEF)]

    strategies = set()
    for seed in range(300):
        data, info = Framework(verbose=False).build(
            Scalar, mode='field', fields=['value'], seed=seed,
        )
        assert data != struct.pack('<I', 0xDEADBEEF)
        strategies.add(info.mutations[0].strategy)

    assert {
        'small_integer', 'one_hot', 'one_cold', 'nominal_bit_flip',
        'repeated_byte', 'magic', 'partial_width', 'byte_swap', 'random',
    } <= strategies


@pytest.mark.parametrize('field_type', [
    FieldType.SBYTE,
    FieldType.SWORD,
    FieldType.SDWORD,
    FieldType.SQWORD,
    FieldType.VARINT_SIGNED,
    FieldType.SLEB128,
])
def test_new_integer_payloads_stay_in_signed_domain(field_type):
    limits = {
        FieldType.SBYTE: (-128, 127),
        FieldType.SWORD: (-32768, 32767),
        FieldType.SDWORD: (-2147483648, 2147483647),
        FieldType.SQWORD: (-(1 << 63), (1 << 63) - 1),
        FieldType.VARINT_SIGNED: (-(1 << 63), (1 << 63) - 1),
        FieldType.SLEB128: (-(1 << 63), (1 << 63) - 1),
    }
    minimum, maximum = limits[field_type]
    for seed in range(100):
        value, _ = get_fuzz_integer(field_type, -17, random.Random(seed))
        assert minimum <= value <= maximum
        assert value != -17


def test_one_byte_blind_fuzzing_is_safe_and_reported():
    class OneByte(Packet):
        fields = [Field('value', FieldType.BYTE, 0, fuzz=False)]

    for seed in range(20):
        data, info = Framework(verbose=False).build(OneByte, mode='blind', seed=seed)
        assert data != b'\x00'
        assert len(info.mutations) == 1
        assert info.mutations[0].strategy.startswith('blind_')


def test_array_fallback_and_packet_expansion_are_safe_and_reported():
    class Fixed(Packet):
        fields = [Field('items', FieldType.ARRAY, [1, 2],
                        element=FieldType.BYTE, element_size=1)]

    class Item(Packet):
        fields = [Field('value', FieldType.BYTE, 7)]

    class Nested(Packet):
        fields = [Field('items', FieldType.ARRAY, [Item()], element=Item)]

    fw = Framework(verbose=False)
    _, info = fw.build(Fixed, mode='array', fields=['items'],
                       array_expand=True, array_max=2, seed=2)
    assert info.array_expansions == ['items']

    data, info = fw.build(Nested, mode='array', fields=['items'],
                          array_expand=True, array_max=3, seed=3)
    assert len(data) in (2, 3)
    assert info.array_expansions == ['items']


def test_per_build_seed_reproduces_data_and_metadata():
    class Repro(Packet):
        fields = [
            Field('left', FieldType.DWORD, 1),
            Field('right', FieldType.BYTES, b'abc'),
        ]

    fw = Framework(verbose=False)
    first_data, first_info = fw.build(Repro, mode='full', seed=0xBAD5EED)
    second_data, second_info = fw.build(Repro, mode='full', seed=0xBAD5EED)
    assert second_data == first_data
    assert second_info == first_info
    assert first_info.seed == 0xBAD5EED


def test_mutation_locations_and_mutable_defaults():
    class Located(Packet):
        fields = [
            Field('prefix', FieldType.BYTE, 1, fuzz=False),
            Field('value', FieldType.WORD, 2),
        ]

    _, info = Framework(verbose=False).build(
        Located, mode='field', fields=['value'], seed=4,
    )
    assert (info.mutations[0].offset, info.mutations[0].size) == (1, 2)

    class Defaults(Packet):
        fields = [Field('items', FieldType.ARRAY, [1], element_size=1)]

    first = Defaults()
    second = Defaults()
    first.get_value('items').append(2)
    assert second.get_value('items') == [1]


def test_invalid_relationships_fail_loudly():
    with pytest.raises(ValueError, match='requires target'):
        Field('broken', FieldType.LENGTH)

    class MissingTarget(Packet):
        fields = [
            Field('length', FieldType.LENGTH, target='missing'),
            Field('data', FieldType.BYTES, b'x'),
        ]

    with pytest.raises(ValueError, match='not found'):
        Framework(verbose=False).build_clean(MissingTarget)


def test_explicit_semantic_varint_can_use_length_mode():
    class QUICLike(Packet):
        fields = [
            Field('length', FieldType.VARINT, 3),
            Field('data', FieldType.BYTES, b'abc', fuzz=False),
        ]

    data, info = Framework(verbose=False).build(
        QUICLike, mode='length', fields=['length'], seed=9,
    )
    assert info.mutations[0].field == 'length'
    assert info.length_mismatches == ['length']
    assert data != b'\x03abc'


def test_explicit_none_can_omit_a_non_none_optional_default():
    class Optional(Packet):
        fields = [Field('value', FieldType.DER_INTEGER, 7,
                        optional=True, fuzz=False)]

    fw = Framework(verbose=False)
    assert fw.build_clean(Optional) == b'\x02\x01\x07'
    assert fw.build_clean(Optional, {'value': None}) == b''


def test_empty_packet_blind_mode_still_produces_a_reproducible_case():
    class Empty(Packet):
        fields = []

    data, info = Framework(verbose=False).build(Empty, mode='blind', seed=14)
    assert data
    assert info.mutations[0].strategy == 'blind_extend'
    replay, replay_info = Framework(verbose=False).build(Empty, mode='blind', seed=14)
    assert (replay, replay_info) == (data, info)


def test_framework_constructor_seed_reproduces_a_sequence():
    class Scalar(Packet):
        fields = [Field('value', FieldType.DWORD, 1)]

    first = Framework(verbose=False, seed=123)
    second = Framework(verbose=False, seed=123)
    assert [first.build(Scalar, mode='field') for _ in range(3)] == [
        second.build(Scalar, mode='field') for _ in range(3)
    ]
    with pytest.raises(ValueError, match='either seed or rng'):
        Framework(seed=1, rng=random.Random(1))


@pytest.mark.parametrize('kwargs,error', [
    ({'packet_class': object}, TypeError),
    ({'values': []}, TypeError),
    ({'fields': 'value'}, TypeError),
    ({'fields': [1]}, TypeError),
    ({'seed': 'one'}, TypeError),
    ({'fuzz_count': -1}, ValueError),
    ({'byteflip_count': -1}, ValueError),
    ({'array_max': -1}, ValueError),
])
def test_framework_rejects_invalid_build_arguments(kwargs, error):
    class Scalar(Packet):
        fields = [Field('value', FieldType.BYTE, 1)]

    packet_class = kwargs.pop('packet_class', Scalar)
    with pytest.raises(error):
        Framework(verbose=False).build(packet_class, **kwargs)


def test_declaration_validation_rejects_ambiguous_fields():
    with pytest.raises(ValueError, match='element'):
        Field('items', FieldType.ARRAY)
    with pytest.raises(ValueError, match='both size'):
        Field('data', FieldType.BYTES, size=1, size_from='declared')
    with pytest.raises(ValueError, match='fixed-width'):
        Field('length', FieldType.LENGTH, target='data', size_type=FieldType.VARINT)
    with pytest.raises(ValueError, match='Packet class'):
        Field('inner', FieldType.STRUCT, element=dict)


def test_clean_unsigned_integer_overflow_is_not_silently_truncated():
    class Overflow(Packet):
        fields = [Field('value', FieldType.BYTE, 256)]

    with pytest.raises(OverflowError, match='does not fit'):
        Framework(verbose=False).build_clean(Overflow)

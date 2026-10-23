"""Wire-format coverage across the supported declarative field matrix."""

import struct

import pytest

from offbywon import Field, FieldType, Framework, Marker, Packet


def build_one(field, value=None):
    packet = Packet.from_fields([field])
    values = None if value is None else {field.name: value}
    return Framework(verbose=False).build_clean(
        lambda_values_packet(packet), values,
    )


def lambda_values_packet(template):
    """Create a normal Packet subclass from a dynamic Packet's cloned fields."""
    return type('DynamicPacket', (Packet,), {'fields': template.iter_fields()})


@pytest.mark.parametrize('field,value,expected', [
    (Field('v', FieldType.BYTE), 0xfe, b'\xfe'),
    (Field('v', FieldType.SBYTE), -2, b'\xfe'),
    (Field('v', FieldType.WORD), 0x1234, b'\x34\x12'),
    (Field('v', FieldType.SWORD), -2, b'\xfe\xff'),
    (Field('v', FieldType.DWORD), 0x12345678, b'\x78\x56\x34\x12'),
    (Field('v', FieldType.SDWORD), -2, b'\xfe\xff\xff\xff'),
    (Field('v', FieldType.QWORD), 0x0102030405060708, b'\x08\x07\x06\x05\x04\x03\x02\x01'),
    (Field('v', FieldType.SQWORD), -2, b'\xfe\xff\xff\xff\xff\xff\xff\xff'),
    (Field('v', FieldType.WORD_BE), 0x1234, b'\x12\x34'),
    (Field('v', FieldType.DWORD_BE), 0x12345678, b'\x12\x34\x56\x78'),
    (Field('v', FieldType.QWORD_BE), 0x0102030405060708, b'\x01\x02\x03\x04\x05\x06\x07\x08'),
    (Field('v', FieldType.VARINT), 63, b'\x3f'),
    (Field('v', FieldType.VARINT), 64, b'\x40\x40'),
    (Field('v', FieldType.VARINT), 16384, b'\x80\x00\x40\x00'),
    (Field('v', FieldType.ULEB128), 624485, b'\xe5\x8e\x26'),
    (Field('v', FieldType.SLEB128), -624485, b'\x9b\xf1\x59'),
])
def test_clean_scalar_wire_encodings(field, value, expected):
    assert build_one(field, value) == expected


@pytest.mark.parametrize('ftype,value', [
    (FieldType.BYTE, 1),
    (FieldType.SBYTE, -1),
    (FieldType.WORD, 1),
    (FieldType.SWORD, -1),
    (FieldType.DWORD, 1),
    (FieldType.SDWORD, -1),
    (FieldType.QWORD, 1),
    (FieldType.SQWORD, -1),
    (FieldType.WORD_BE, 1),
    (FieldType.DWORD_BE, 1),
    (FieldType.QWORD_BE, 1),
    (FieldType.VARINT, 1),
    (FieldType.VARINT_SIGNED, -1),
    (FieldType.ULEB128, 1),
    (FieldType.SLEB128, -1),
])
def test_every_integer_serializer_has_a_real_fuzz_path(ftype, value):
    class IntegerPacket(Packet):
        fields = [Field('value', ftype, value)]

    fw = Framework(verbose=False)
    clean = fw.build_clean(IntegerPacket)
    fuzzed, info = fw.build(
        IntegerPacket, mode='field', fields=['value'], seed=12345,
    )
    assert info.mutations
    assert fuzzed != clean


def test_data_guid_padding_and_reserved_encodings():
    class DataPacket(Packet):
        fields = [
            Marker('start'),
            Field('raw', FieldType.BYTES, b'ab', size=4, fuzz=False),
            Field('text', FieldType.STRING, 'A', encoding='ascii',
                  null_terminated=True, size=3, fuzz=False),
            Field('guid', FieldType.GUID, '00112233-4455-6677-8899-aabbccddeeff', fuzz=False),
            Field('reserved', FieldType.RESERVED, size=2, fuzz=False),
            Field('padding', FieldType.PADDING, align=4, relative_to='start'),
        ]

    data = Framework(verbose=False).build_clean(DataPacket)
    assert data[:7] == b'ab\x00\x00A\x00\x00'
    assert data[7:23] == bytes.fromhex('33221100554477668899aabbccddeeff')
    assert data[23:25] == b'\x00\x00'
    assert len(data) == 28


@pytest.mark.parametrize('name,field,default', [
    ('raw', Field('raw', FieldType.BYTES, b'abc', size=3), b'abc'),
    ('text', Field('text', FieldType.STRING, 'abc', encoding='ascii', size=3), b'abc'),
    ('guid', Field('guid', FieldType.GUID, b'\x00' * 16), b'\x00' * 16),
    ('reserved', Field('reserved', FieldType.RESERVED, size=0), b''),
])
def test_data_fields_always_change_when_selected(name, field, default):
    Dynamic = type('Dynamic', (Packet,), {'fields': [field]})
    fw = Framework(verbose=False)
    assert fw.build_clean(Dynamic) == default
    fuzzed, info = fw.build(Dynamic, mode='field', fields=[name], seed=99)
    assert info.mutations
    assert fuzzed != default


def test_offset_relative_skip_and_self_inclusive_length():
    class Relations(Packet):
        fields = [
            Marker('base'),
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.WORD,
                  includes_self=True),
            Field('relative', FieldType.OFFSET, target='data', relative=True,
                  skip=1, size_type=FieldType.WORD),
            Field('absolute', FieldType.OFFSET, target='data', base='base',
                  size_type=FieldType.WORD),
            Field('data', FieldType.BYTES, b'xyz'),
        ]

    data = Framework(verbose=False).build_clean(Relations)
    assert struct.unpack('<HHH', data[:6]) == (5, 5, 6)


def test_relationship_values_must_fit_their_wire_width():
    class TooLong(Packet):
        fields = [
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.BYTE),
            Field('data', FieldType.BYTES, b'A' * 256),
        ]

    with pytest.raises(OverflowError, match='does not fit'):
        Framework(verbose=False).build_clean(TooLong)


def test_missing_padding_marker_is_an_error():
    class BrokenPadding(Packet):
        fields = [Field('padding', FieldType.PADDING, align=4, relative_to='missing')]

    with pytest.raises(ValueError, match='PADDING base'):
        Framework(verbose=False).build_clean(BrokenPadding)


def test_union_with_nested_packet_and_raw_fallback_can_be_fuzzed():
    class Body(Packet):
        fields = [Field('number', FieldType.WORD, 7)]

    class NestedUnion(Packet):
        fields = [
            Field('kind', FieldType.BYTE, 1, fuzz=False),
            Field('body', FieldType.UNION, {'number': 7}, selector='kind',
                  choices={1: Body}),
        ]

    _, info = Framework(verbose=False).build(
        NestedUnion, mode='field', fields=['body'], seed=11,
    )
    assert info.mutations[0].field == 'body.number'

    class RawUnion(Packet):
        fields = [Field('body', FieldType.UNION, b'abc', element=b'raw')]

    clean = Framework(verbose=False).build_clean(RawUnion)
    fuzzed, info = Framework(verbose=False).build(
        RawUnion, mode='field', fields=['body'], seed=12,
    )
    assert info.mutations and fuzzed != clean


def test_packet_can_be_serialized_clean_after_a_fuzzed_fixup():
    from offbywon import FuzzMode, Serializer, SerializerContext

    class Reused(Packet):
        fields = [
            Field('length', FieldType.LENGTH, target='data', size_type=FieldType.BYTE),
            Field('data', FieldType.BYTES, b'abc'),
        ]

    packet = Reused()
    fuzz_context = SerializerContext(FuzzMode.LENGTH)
    fuzz_context.target_fields = ['length']
    Serializer().serialize(packet, fuzz_context)

    clean_context = SerializerContext(FuzzMode.CLEAN)
    Serializer().serialize(packet, clean_context)
    assert clean_context.get_bytes() == b'\x03abc'

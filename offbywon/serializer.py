"""
OffByWon Framework - Packet Serializer

Handles serialization of Field definitions to bytes, including:
- Length/Count/Offset resolution
- Nested structure handling
- DER encoding
- NDR encoding
"""

import struct
import random
import copy
import re
from typing import Any, Dict, List, Optional, Tuple
from io import BytesIO

from .types import (
    FieldType, FuzzMode, Mutation,
    FIELD_TYPE_SIZES, get_fuzz_integer, get_fuzz_buffer,
    COUNT_VALUES, LENGTH_DELTAS, OFFSET_CORRUPTIONS,
)
from .packet import Field, Marker, Packet
from . import der


class SerializerContext:
    """
    Context for packet serialization.
    
    Tracks:
    - Current byte position
    - Marker positions
    - Pending length/offset fixups
    - Mutations applied
    """
    
    def __init__(self, fuzz_mode: FuzzMode = FuzzMode.CLEAN, rng=None):
        self.buffer = BytesIO()
        self.position = 0
        self.markers: Dict[str, int] = {}
        self.field_positions: Dict[str, Tuple[int, int]] = {}  # qualified name -> (offset, size)
        self.field_values: Dict[str, Any] = {}
        self.array_counts: Dict[str, int] = {}
        self.fixups: List[Tuple[str, int, Field, str]] = []  # type, position, field, scope
        self.mutations: List[Mutation] = []
        self.array_expansions: List[str] = []
        self.fuzz_mode = fuzz_mode
        self.rng = rng if rng is not None else random.Random()
        self.array_expand = False
        self.array_max = 65535
        self.fuzz_count = None
        self.target_fields = None
        self.explicit_mode_override = False
        self._fields_fuzzed = 0
        self._fuzzed_paths = set()
        self._fuzz_decisions: Dict[str, bool] = {}
        self._scope: List[str] = []
    
    def write(self, data: bytes):
        """Write bytes to buffer."""
        self.buffer.write(data)
        self.position += len(data)
    
    def tell(self) -> int:
        """Get current position."""
        return self.position
    
    def seek(self, pos: int):
        """Seek to position."""
        self.buffer.seek(pos)
    
    def write_at(self, pos: int, data: bytes):
        """Write at specific position without advancing."""
        current = self.buffer.tell()
        self.buffer.seek(pos)
        self.buffer.write(data)
        self.buffer.seek(current)
    
    def get_bytes(self) -> bytes:
        """Get complete buffer contents."""
        return self.buffer.getvalue()
    
    @property
    def current_scope(self) -> str:
        return '.'.join(self._scope)

    def push_scope(self, name: str):
        if name:
            self._scope.append(name)

    def pop_scope(self):
        if self._scope:
            self._scope.pop()

    def qualify(self, name: str, scope: str = None) -> str:
        scope = self.current_scope if scope is None else scope
        return f"{scope}.{name}" if scope else name

    def _resolve_key(self, mapping: Dict[str, Any], name: str, scope: str = None) -> Optional[str]:
        """Resolve a local, dotted, or ancestor-relative field reference."""
        scope = self.current_scope if scope is None else scope
        candidates = []
        if scope:
            current = scope
            while current:
                candidates.append(f"{current}.{name}")
                current = current.rsplit('.', 1)[0] if '.' in current else ''
        candidates.append(name)
        for candidate in candidates:
            if candidate in mapping:
                return candidate
        return None

    def set_marker(self, name: str):
        """Set a marker at current position."""
        self.markers[self.qualify(name)] = self.position
    
    def get_marker(self, name: str, scope: str = None) -> Optional[int]:
        """Get marker position."""
        key = self._resolve_key(self.markers, name, scope)
        return self.markers.get(key) if key is not None else None
    
    def record_field(self, name: str, offset: int, size: int):
        """Record field position and size."""
        self.field_positions[name] = (offset, size)
    
    def get_field_position(self, name: str, scope: str = None) -> Optional[Tuple[int, int]]:
        """Get field position and size."""
        key = self._resolve_key(self.field_positions, name, scope)
        return self.field_positions.get(key) if key is not None else None

    def record_value(self, name: str, value: Any):
        self.field_values[name] = value

    def get_field_value(self, name: str, scope: str = None) -> Any:
        key = self._resolve_key(self.field_values, name, scope)
        return self.field_values.get(key) if key is not None else None

    def record_array_count(self, name: str, count: int):
        self.array_counts[name] = count

    def get_array_count(self, name: str, scope: str = None) -> Optional[int]:
        key = self._resolve_key(self.array_counts, name, scope)
        return self.array_counts.get(key) if key is not None else None
    
    def add_fixup(self, fixup_type: str, position: int, field: Field):
        """Add a fixup to resolve later."""
        self.fixups.append((fixup_type, position, field, self.current_scope))

    @staticmethod
    def type_is_fuzzable(mode: FuzzMode, ftype: FieldType) -> bool:
        """Return whether a mode is allowed to mutate this field type."""
        if mode in (FuzzMode.CLEAN, FuzzMode.BLIND, FuzzMode.BYTEFLIP):
            return False
        if ftype in (FieldType.STRUCT, FieldType.PADDING):
            return False  # its children are selected independently
        if mode == FuzzMode.LENGTH:
            return ftype in (FieldType.LENGTH, FieldType.COUNT, FieldType.OFFSET)
        if mode == FuzzMode.ARRAY:
            return ftype in (FieldType.ARRAY, FieldType.COUNT)
        return True

    @staticmethod
    def type_is_numeric(ftype: FieldType) -> bool:
        return ftype in (
            FieldType.BYTE, FieldType.SBYTE, FieldType.WORD, FieldType.SWORD,
            FieldType.DWORD, FieldType.SDWORD, FieldType.QWORD, FieldType.SQWORD,
            FieldType.WORD_BE, FieldType.DWORD_BE, FieldType.QWORD_BE,
            FieldType.VARINT, FieldType.VARINT_SIGNED,
            FieldType.ULEB128, FieldType.SLEB128,
        )

    @staticmethod
    def _target_matches(target: str, path: str, bare_name: str) -> bool:
        if target == path:
            return True
        if path.startswith(target + '.'):
            return True
        # Selecting an ARRAY field also selects one of its emitted elements.
        if path.startswith(target + '['):
            return True
        if '.' not in target and '[' not in target and target == bare_name:
            return True
        if '[]' in target:
            pattern = '^' + re.escape(target).replace(r'\[\]', r'\[\d+\]') + '$'
            return re.match(pattern, path) is not None
        return False
    
    def should_fuzz_field(self, field: Field) -> bool:
        """Determine if this specific field should be fuzzed."""
        path = getattr(field, '_path', self.qualify(field.name))
        if path in self._fuzz_decisions:
            return self._fuzz_decisions[path]

        target_match = self.target_fields is not None and any(
            self._target_matches(target, path, field.name) for target in self.target_fields
        )
        eligible = self.type_is_fuzzable(self.fuzz_mode, field.type)
        if (not eligible and self.explicit_mode_override and target_match
                and self.fuzz_mode in (FuzzMode.LENGTH, FuzzMode.ARRAY)
                and self.type_is_numeric(field.type)):
            # Some protocols encode semantic lengths/offsets/counts in a native
            # scalar (for example a QUIC VARINT). Explicit targeting opts that
            # scalar into relation fuzzing without letting automatic selection
            # wander into arbitrary numeric fields.
            eligible = True
        if not eligible:
            self._fuzz_decisions[path] = False
            return False
        if not field.fuzz:
            self._fuzz_decisions[path] = False
            return False
        if self.target_fields is not None and not target_match:
            self._fuzz_decisions[path] = False
            return False
        if self.fuzz_count is not None and self._fields_fuzzed >= self.fuzz_count:
            self._fuzz_decisions[path] = False
            return False
        
        # When fuzz_count is set, don't do random selection - fuzz until we hit the count
        if self.fuzz_count is not None:
            self._fuzz_decisions[path] = True
            return True
        
        # Random selection when not targeting specific fields and no fuzz_count
        if self.target_fields is None:
            if self.rng.random() > 0.3:  # direct Serializer users retain stochastic selection
                self._fuzz_decisions[path] = False
                return False
        self._fuzz_decisions[path] = True
        return True
    
    def record_fuzz(self, field: Field):
        """Record that a field was fuzzed."""
        path = getattr(field, '_path', self.qualify(field.name))
        if path not in self._fuzzed_paths:
            self._fuzzed_paths.add(path)
            self._fields_fuzzed += 1


class Serializer:
    """
    Packet serializer.
    
    Converts Field definitions to bytes, handling:
    - Integer encoding (little/big endian)
    - Variable-length integers (varint, LEB128)
    - Length/Count/Offset fields with automatic resolution
    - Nested structures
    - Arrays with element handling
    - DER/ASN.1 encoding
    - NDR encoding
    """
    
    def serialize(self, packet: Packet, ctx: SerializerContext, scope: str = None) -> bytes:
        """
        Serialize a packet to bytes.
        
        Args:
            packet: Packet instance to serialize
            ctx: Serialization context
        
        Returns:
            Serialized bytes
        """
        if scope:
            ctx.push_scope(scope)
        start_pos = ctx.tell()
        fixup_start = len(ctx.fixups)

        try:
            for item in packet.iter_fields():
                if isinstance(item, Marker):
                    ctx.set_marker(item.name)
                    item._offset = ctx.tell()
                elif isinstance(item, Field):
                    self._serialize_field(item, ctx)

            # Resolve only the fixups created in this packet scope. Parent
            # fixups remain pending, and sibling packets can safely reuse names.
            self._apply_fixups(ctx, fixup_start)
            del ctx.fixups[fixup_start:]
            return ctx.get_bytes()[start_pos:]
        finally:
            if scope:
                ctx.pop_scope()
    
    def _serialize_field(self, field: Field, ctx: SerializerContext):
        """Serialize a single field."""
        field_start = ctx.tell()
        field._offset = field_start
        field._path = ctx.qualify(field.name)
        field._scope = ctx.current_scope
        mutation_start = len(ctx.mutations)
        
        # Get value (runtime or default)
        value = field.value
        
        # Determine if we should fuzz this field
        should_fuzz = ctx.should_fuzz_field(field)
        
        # Serialize based on type
        if field.type in (FieldType.BYTE, FieldType.SBYTE):
            self._serialize_byte(field, value, ctx, should_fuzz)
        elif field.type in (FieldType.WORD, FieldType.SWORD):
            self._serialize_word(field, value, ctx, should_fuzz)
        elif field.type in (FieldType.DWORD, FieldType.SDWORD):
            self._serialize_dword(field, value, ctx, should_fuzz)
        elif field.type in (FieldType.QWORD, FieldType.SQWORD):
            self._serialize_qword(field, value, ctx, should_fuzz)
        elif field.type == FieldType.WORD_BE:
            self._serialize_word_be(field, value, ctx, should_fuzz)
        elif field.type == FieldType.DWORD_BE:
            self._serialize_dword_be(field, value, ctx, should_fuzz)
        elif field.type == FieldType.QWORD_BE:
            self._serialize_qword_be(field, value, ctx, should_fuzz)
        elif field.type == FieldType.VARINT:
            self._serialize_varint(field, value, ctx, should_fuzz)
        elif field.type == FieldType.VARINT_SIGNED:
            self._serialize_varint_signed(field, value, ctx, should_fuzz)
        elif field.type == FieldType.ULEB128:
            self._serialize_uleb128(field, value, ctx, should_fuzz)
        elif field.type == FieldType.SLEB128:
            self._serialize_sleb128(field, value, ctx, should_fuzz)
        elif field.type == FieldType.BYTES:
            self._serialize_bytes(field, value, ctx, should_fuzz)
        elif field.type == FieldType.STRING:
            self._serialize_string(field, value, ctx, should_fuzz)
        elif field.type == FieldType.GUID:
            self._serialize_guid(field, value, ctx, should_fuzz)
        elif field.type == FieldType.LENGTH:
            self._serialize_length(field, value, ctx, should_fuzz)
        elif field.type == FieldType.COUNT:
            self._serialize_count(field, value, ctx, should_fuzz)
        elif field.type == FieldType.OFFSET:
            self._serialize_offset(field, value, ctx, should_fuzz)
        elif field.type == FieldType.PADDING:
            self._serialize_padding(field, ctx)
        elif field.type == FieldType.RESERVED:
            self._serialize_reserved(field, ctx, should_fuzz)
        elif field.type == FieldType.ARRAY:
            self._serialize_array(field, value, ctx, should_fuzz)
        elif field.type == FieldType.STRUCT:
            self._serialize_struct(field, value, ctx)
        elif field.type == FieldType.UNION:
            self._serialize_union(field, value, ctx, should_fuzz)
        elif field.type.name.startswith('DER_'):
            self._serialize_der(field, value, ctx, should_fuzz)
        elif field.type.name.startswith('NDR_'):
            self._serialize_ndr(field, value, ctx, should_fuzz)
        else:
            raise ValueError(f"Unknown field type: {field.type}")
        
        field._size = ctx.tell() - field_start
        ctx.record_field(field._path, field_start, field._size)
        ctx.record_value(field._path, getattr(field, '_serialized_value', value))

        # Complete byte location metadata for mutations created while this field
        # was serialized. Fixup mutations fill their own locations later.
        for mutation in ctx.mutations[mutation_start:]:
            if mutation.offset == 0 and mutation.size == 0:
                mutation.offset = field_start
                mutation.size = field._size
    
    # =========================================================================
    # Integer Serialization
    # =========================================================================

    @staticmethod
    def _validate_integer(field: Field, value: Any, minimum: int, maximum: int) -> int:
        if not isinstance(value, int):
            raise TypeError(f"field {field._path!r} requires an integer value")
        if not minimum <= value <= maximum:
            raise OverflowError(
                f"value {value!r} does not fit {field.type.name} field {field._path!r}"
            )
        return value
    
    def _serialize_byte(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize BYTE/SBYTE."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        if field.type == FieldType.SBYTE:
            self._validate_integer(field, value, -0x80, 0x7f)
            ctx.write(struct.pack('<b', value))
        else:
            self._validate_integer(field, value, 0, 0xff)
            ctx.write(struct.pack('<B', value))
    
    def _serialize_word(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize WORD/SWORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        if field.type == FieldType.SWORD:
            self._validate_integer(field, value, -0x8000, 0x7fff)
            ctx.write(struct.pack('<h', value))
        else:
            self._validate_integer(field, value, 0, 0xffff)
            ctx.write(struct.pack('<H', value))
    
    def _serialize_dword(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize DWORD/SDWORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        if field.type == FieldType.SDWORD:
            self._validate_integer(field, value, -0x80000000, 0x7fffffff)
            ctx.write(struct.pack('<i', value))
        else:
            self._validate_integer(field, value, 0, 0xffffffff)
            ctx.write(struct.pack('<I', value))
    
    def _serialize_qword(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize QWORD/SQWORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        if field.type == FieldType.SQWORD:
            self._validate_integer(field, value, -(1 << 63), (1 << 63) - 1)
            ctx.write(struct.pack('<q', value))
        else:
            self._validate_integer(field, value, 0, (1 << 64) - 1)
            ctx.write(struct.pack('<Q', value))
    
    def _serialize_word_be(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize big-endian WORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        self._validate_integer(field, value, 0, 0xffff)
        ctx.write(struct.pack('>H', value))
    
    def _serialize_dword_be(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize big-endian DWORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        self._validate_integer(field, value, 0, 0xffffffff)
        ctx.write(struct.pack('>I', value))
    
    def _serialize_qword_be(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize big-endian QWORD."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        field._serialized_value = value
        self._validate_integer(field, value, 0, (1 << 64) - 1)
        ctx.write(struct.pack('>Q', value))
    
    # =========================================================================
    # Variable-Length Integer Serialization
    # =========================================================================
    
    def _serialize_varint(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize QUIC-style variable-length integer."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(field.type, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        self._validate_integer(field, value, 0, 4611686018427387903)
        field._serialized_value = value
        # QUIC varint: 2-bit prefix indicates length
        if value <= 63:
            ctx.write(bytes([value]))
        elif value <= 16383:
            ctx.write(struct.pack('>H', 0x4000 | value))
        elif value <= 1073741823:
            ctx.write(struct.pack('>I', 0x80000000 | value))
        else:
            ctx.write(struct.pack('>Q', 0xC000000000000000 | value))
    
    @staticmethod
    def _encode_uleb128(value: int) -> bytes:
        if value < 0:
            raise ValueError("ULEB128 value cannot be negative")
        result = []
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                byte |= 0x80
            result.append(byte)
            if not value:
                return bytes(result)

    def _serialize_varint_signed(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a protobuf-style ZigZag signed varint."""
        if value is None:
            value = 0
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(FieldType.SQWORD, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        self._validate_integer(field, value, -(1 << 63), (1 << 63) - 1)
        field._serialized_value = value
        zigzag = (value << 1) ^ (value >> 63)
        ctx.write(self._encode_uleb128(zigzag))

    def _serialize_uleb128(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize unsigned LEB128."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(FieldType.QWORD, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        if not isinstance(value, int):
            raise TypeError(f"field {field._path!r} requires an integer value")
        field._serialized_value = value
        ctx.write(self._encode_uleb128(value))
    
    def _serialize_sleb128(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize signed LEB128."""
        if value is None:
            value = 0
        
        if fuzz:
            fuzzed, strategy = get_fuzz_integer(FieldType.SQWORD, value, ctx.rng)
            ctx.mutations.append(Mutation(field._path, value, fuzzed, strategy))
            ctx.record_fuzz(field)
            value = fuzzed
        
        if not isinstance(value, int):
            raise TypeError(f"field {field._path!r} requires an integer value")
        field._serialized_value = value
        result = []
        more = True
        while more:
            byte = value & 0x7F
            value >>= 7
            if (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
                more = False
            else:
                byte |= 0x80
            result.append(byte)
        ctx.write(bytes(result))
    
    # =========================================================================
    # Data Serialization
    # =========================================================================

    def _effective_size(self, field: Field, ctx: SerializerContext) -> Optional[int]:
        if field.size is not None:
            return field.size
        if field.size_from:
            size = ctx.get_field_value(field.size_from, field._scope)
            if size is None:
                raise ValueError(
                    f"size_from={field.size_from!r} for {field._path!r} "
                    "must reference an earlier integer field"
                )
            if not isinstance(size, int) or size < 0:
                raise ValueError(f"invalid size {size!r} for {field._path!r}")
            return size
        return None
    
    def _serialize_bytes(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize raw bytes."""
        if value is None:
            value = b''
        if isinstance(value, str):
            value = value.encode('utf-8')
        elif isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value)
        else:
            raise TypeError(f"BYTES field {field._path!r} requires a bytes-like value")
        
        effective_size = self._effective_size(field, ctx)
        clean_value = value
        if effective_size is not None:
            clean_value = clean_value[:effective_size].ljust(effective_size, b'\x00')

        if fuzz:
            nominal_size = effective_size if effective_size is not None else (len(value) or 16)
            fuzzed = clean_value
            strategy = 'alternate_byte'
            for _ in range(8):
                fuzzed, strategy = get_fuzz_buffer(nominal_size, rng=ctx.rng)
                if fuzzed != clean_value:
                    break
            if fuzzed == clean_value:
                fuzzed = (bytes([clean_value[0] ^ 0xff]) + clean_value[1:]
                          if clean_value else b'\xff')
                strategy = 'alternate_byte'
            value = fuzzed
            ctx.mutations.append(Mutation(
                field._path, f"({len(clean_value)} bytes)",
                f"({len(value)} bytes)", strategy,
            ))
            ctx.record_fuzz(field)
        else:
            value = clean_value
        
        field._serialized_value = value
        ctx.write(value)
    
    def _serialize_string(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a string with encoding."""
        if value is None:
            value = ''
        if not isinstance(value, str):
            value = str(value)
        
        original_value = value
        if fuzz:
            strategy = ctx.rng.choice(['overflow', 'empty', 'unicode', 'null_injection'])
            if strategy == 'overflow':
                value = value + 'A' * ctx.rng.choice([100, 500, 1000, 5000])
            elif strategy == 'empty':
                value = ''
            elif strategy == 'unicode':
                value = value + '\u0000\uffff\ud800'  # Null + invalid surrogates
            elif strategy == 'null_injection':
                value = value[:len(value)//2] + '\x00' + value[len(value)//2:]
        null = b'\x00\x00' if 'utf-16' in field.encoding else b'\x00'

        def encode_string(text: str) -> bytes:
            result = text.encode(field.encoding, errors='replace')
            if field.null_terminated and not result.endswith(null):
                result += null
            return result

        clean_encoded = encode_string(original_value)
        effective_size = self._effective_size(field, ctx)
        if effective_size is not None:
            clean_encoded = clean_encoded[:effective_size].ljust(effective_size, b'\x00')

        if fuzz:
            encoded = encode_string(value)
            if encoded == clean_encoded:
                value += 'A'
                encoded = encode_string(value)
                strategy = 'alternate_character'
            ctx.mutations.append(Mutation(
                field._path, original_value, value, strategy,
            ))
            ctx.record_fuzz(field)
        else:
            encoded = clean_encoded
        
        field._serialized_value = value
        ctx.write(encoded)
    
    def _serialize_guid(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a GUID (16 bytes, Microsoft format)."""
        if value is None:
            value = b'\x00' * 16
        elif isinstance(value, str):
            # Parse UUID string
            value = bytes.fromhex(value.replace('-', ''))
            # Convert to Microsoft GUID format (little-endian first 3 parts)
            value = (value[3::-1] + value[5:3:-1] + value[7:5:-1] + value[8:])
        elif isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value)
        else:
            raise TypeError(f"GUID field {field._path!r} requires a UUID string or bytes")
        
        value = value[:16].ljust(16, b'\x00')
        original_value = value
        if fuzz:
            strategy = 'alternate_byte'
            for _ in range(8):
                strategy = ctx.rng.choice(['zero', 'ones', 'random', 'boundary'])
                if strategy == 'zero':
                    value = b'\x00' * 16
                elif strategy == 'ones':
                    value = b'\xff' * 16
                elif strategy == 'random':
                    value = bytes(ctx.rng.randint(0, 255) for _ in range(16))
                elif strategy == 'boundary':
                    value = b'\xff\xff\xff\x7f' + b'\xff' * 12
                if value != original_value:
                    break
            if value == original_value:
                value = bytes([value[0] ^ 0xff]) + value[1:]
                strategy = 'alternate_byte'
            ctx.mutations.append(Mutation(field._path, "(guid)", f"({strategy})", strategy))
            ctx.record_fuzz(field)
        
        field._serialized_value = value
        ctx.write(value)
    
    # =========================================================================
    # Structural Fields
    # =========================================================================
    
    def _serialize_length(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a LENGTH field (will be fixed up later)."""
        pos = ctx.tell()
        size = FIELD_TYPE_SIZES.get(field.size_type, 4)
        
        # Write placeholder
        ctx.write(b'\x00' * size)
        
        # Record for fixup
        ctx.add_fixup('length', pos, field)
        
        field._fuzz_length = bool(fuzz)
        if fuzz:
            ctx.record_fuzz(field)
    
    def _serialize_count(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a COUNT field (will be fixed up later)."""
        pos = ctx.tell()
        size = FIELD_TYPE_SIZES.get(field.size_type, 4)
        
        # Write placeholder
        ctx.write(b'\x00' * size)
        
        # Record for fixup
        ctx.add_fixup('count', pos, field)
        
        field._fuzz_count = bool(fuzz)
        if fuzz:
            ctx.record_fuzz(field)
    
    def _serialize_offset(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize an OFFSET field (will be fixed up later)."""
        pos = ctx.tell()
        size = FIELD_TYPE_SIZES.get(field.size_type, 4)
        
        # Write placeholder
        ctx.write(b'\x00' * size)
        
        # Record for fixup
        ctx.add_fixup('offset', pos, field)
        
        field._fuzz_offset = bool(fuzz)
        if fuzz:
            ctx.record_fuzz(field)
    
    def _serialize_padding(self, field: Field, ctx: SerializerContext):
        """Serialize alignment padding."""
        align = field.align
        current = ctx.tell()
        
        if field.relative_to:
            base = ctx.get_marker(field.relative_to, field._scope)
            if base is None:
                raise ValueError(
                    f"PADDING base {field.relative_to!r} not found for {field._path!r}"
                )
            current = current - base
        
        remainder = current % align
        if remainder:
            padding = align - remainder
            ctx.write(b'\x00' * padding)
    
    def _serialize_reserved(self, field: Field, ctx: SerializerContext, fuzz: bool):
        """Serialize reserved bytes."""
        size = field.size if field.size is not None else 4
        
        if fuzz:
            value = bytes(ctx.rng.randint(0, 255) for _ in range(size))
            if not size:
                value = b'\xff'
            elif value == b'\x00' * size:
                value = b'\xff' + value[1:]
            ctx.mutations.append(Mutation(field._path, "(reserved)", "(random)", "random"))
            ctx.record_fuzz(field)
        else:
            value = b'\x00' * size
        
        field._serialized_value = value
        ctx.write(value)
    
    def _serialize_array(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize an array of elements."""
        if value is None:
            value = []
        value = list(value)
        original_count = len(value)

        if field.count_from:
            declared_count = ctx.get_field_value(field.count_from, field._scope)
            if declared_count is None:
                raise ValueError(
                    f"count_from={field.count_from!r} for {field._path!r} "
                    "must reference an earlier integer field"
                )
            if not isinstance(declared_count, int) or declared_count < 0:
                raise ValueError(f"invalid count {declared_count!r} for {field._path!r}")
            if declared_count > ctx.array_max:
                raise ValueError(
                    f"count {declared_count} for {field._path!r} exceeds array_max={ctx.array_max}"
                )
            if declared_count < len(value):
                value = value[:declared_count]
            elif declared_count > len(value):
                template = value[0] if value else self._default_element(field)
                value.extend(
                    self._clone_element(template, field)
                    for _ in range(declared_count - len(value))
                )
        
        expanded = False
        # Array expansion fuzzing
        if fuzz and ctx.array_expand and ctx.fuzz_mode in (FuzzMode.ARRAY, FuzzMode.FULL):
            candidates = [c for c in COUNT_VALUES if len(value) < c <= ctx.array_max]
            if candidates:
                expand_count = ctx.rng.choice(candidates)
                # Expand array with copies/variations of existing elements
                template = value[0] if value else self._default_element(field)
                value = [self._clone_element(template, field) for _ in range(expand_count)]
                ctx.mutations.append(Mutation(f"{field._path}[]", f"({original_count} elements)",
                                            f"({len(value)} elements)", "expand"))
                ctx.array_expansions.append(field._path)
                ctx.record_fuzz(field)
                expanded = True

        # ARRAY/FULL mode still performs a structural array mutation when the
        # caller did not request boundary expansion.
        if (fuzz and not expanded and ctx.fuzz_mode in (
                FuzzMode.FIELD, FuzzMode.COMBINED, FuzzMode.ARRAY, FuzzMode.FULL)):
            before = len(value)
            if value and len(value) < ctx.array_max:
                value.insert(ctx.rng.randrange(len(value) + 1), self._clone_element(
                    ctx.rng.choice(value), field
                ))
                strategy = 'duplicate'
            elif value:
                value.pop(ctx.rng.randrange(len(value)))
                strategy = 'remove'
            elif ctx.array_max > 0:
                value.append(self._default_element(field))
                strategy = 'insert'
            else:
                strategy = None
            if strategy:
                ctx.mutations.append(Mutation(
                    f"{field._path}[]", f"({before} elements)",
                    f"({len(value)} elements)", strategy,
                ))
                ctx.array_expansions.append(field._path)
                ctx.record_fuzz(field)
                expanded = True

        ctx.record_array_count(field._path, len(value))
        field._serialized_value = value

        mutate_index = None
        if fuzz and value and not expanded:
            mutate_index = ctx.rng.randrange(len(value))
        
        # Serialize each element
        for i, elem in enumerate(value):
            if field.element_size:
                # Fixed-size simple elements
                if isinstance(elem, int):
                    mask = (1 << (field.element_size * 8)) - 1
                    data = (elem & mask).to_bytes(field.element_size, 'little')
                else:
                    data = bytes(elem)[:field.element_size].ljust(field.element_size, b'\x00')
                
                # Fuzz individual elements
                if fuzz and i == mutate_index:
                    element_type = {
                        1: FieldType.BYTE,
                        2: FieldType.WORD,
                        4: FieldType.DWORD,
                        8: FieldType.QWORD,
                    }.get(field.element_size, FieldType.QWORD)
                    nominal = elem if isinstance(elem, int) else int.from_bytes(data, 'little')
                    mask = (1 << (field.element_size * 8)) - 1
                    fuzzed, strategy = get_fuzz_integer(element_type, nominal & mask, ctx.rng)
                    fuzzed &= mask
                    if fuzzed == nominal & mask:
                        fuzzed ^= mask
                        strategy = 'alternate_boundary'
                    data = fuzzed.to_bytes(field.element_size, 'little')
                    ctx.mutations.append(Mutation(
                        f"{field._path}[{i}]", elem, fuzzed, strategy,
                        ctx.tell(), len(data),
                    ))
                    ctx.record_fuzz(field)
                
                ctx.write(data)
            
            elif isinstance(field.element, type) and issubclass(field.element, Packet):
                # Nested packet elements
                if isinstance(elem, Packet):
                    self.serialize(elem, ctx, scope=f"{field.name}[{i}]")
                else:
                    # elem is a dict or values
                    packet = field.element(elem if isinstance(elem, dict) else {})
                    self.serialize(packet, ctx, scope=f"{field.name}[{i}]")
            
            elif isinstance(field.element, FieldType):
                # Simple type elements
                temp_field = Field(f"{field.name}[{i}]", field.element, elem)
                temp_field.fuzz = field.fuzz
                self._serialize_field(temp_field, ctx)
            
            else:
                # Bytes
                data = bytes(elem) if not isinstance(elem, bytes) else elem
                if fuzz and i == mutate_index:
                    replacement, strategy = get_fuzz_buffer(len(data), rng=ctx.rng)
                    if replacement == data:
                        replacement = (bytes([data[0] ^ 0xff]) + data[1:]
                                       if data else b'\xff')
                    ctx.mutations.append(Mutation(
                        f"{field._path}[{i}]", data, replacement, strategy,
                        ctx.tell(), len(replacement),
                    ))
                    ctx.record_fuzz(field)
                    data = replacement
                ctx.write(data)
    
    def _serialize_struct(self, field: Field, value: Any, ctx: SerializerContext):
        """Serialize a nested structure."""
        if value is None and field.element:
            value = field.element()
        
        if isinstance(value, Packet):
            self.serialize(value, ctx, scope=field.name)
        elif isinstance(value, dict) and field.element:
            packet = field.element(value)
            self.serialize(packet, ctx, scope=field.name)
        elif value is not None:
            raise TypeError(f"STRUCT field {field._path!r} requires a Packet or dict value")

    def _serialize_union(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize a discriminated union using selector= and choices=."""
        selected = field.element
        selector_value = None
        if field.selector:
            selector_value = ctx.get_field_value(field.selector, field._scope)
            if selector_value is None:
                raise ValueError(
                    f"selector={field.selector!r} for {field._path!r} "
                    "must reference an earlier field"
                )
            selected = field.choices.get(selector_value, field.element)
        if selected is None:
            raise ValueError(
                f"no UNION choice for selector value {selector_value!r} in {field._path!r}"
            )
        if isinstance(selected, type) and issubclass(selected, Packet):
            packet = value if isinstance(value, Packet) else selected(value if isinstance(value, dict) else {})
            self.serialize(packet, ctx, scope=field.name)
        elif isinstance(selected, FieldType):
            temp = Field(field.name, selected, value, fuzz=field.fuzz)
            temp._path = field._path
            self._serialize_field(temp, ctx)
        elif isinstance(selected, Field):
            temp = selected.clone()
            temp.name = field.name
            temp.value = value
            self._serialize_field(temp, ctx)
        elif isinstance(value, (bytes, bytearray)):
            data = bytes(value)
            if fuzz:
                replacement, strategy = get_fuzz_buffer(len(data), rng=ctx.rng)
                if replacement == data:
                    replacement = (bytes([data[0] ^ 0xff]) + data[1:]
                                   if data else b'\xff')
                    strategy = 'alternate_byte'
                ctx.mutations.append(Mutation(field._path, data, replacement, strategy))
                ctx.record_fuzz(field)
                data = replacement
            ctx.write(data)
        else:
            raise TypeError(f"unsupported UNION choice {selected!r} for {field._path!r}")
    
    def _default_element(self, field: Field) -> Any:
        """Create a default element for array expansion."""
        if field.element_size:
            return 0
        elif isinstance(field.element, type) and issubclass(field.element, Packet):
            return field.element()
        elif isinstance(field.element, FieldType):
            return 0
        return b'\x00'
    
    def _clone_element(self, template: Any, field: Field) -> Any:
        """Clone an element for array expansion."""
        if isinstance(template, (bytes, bytearray)):
            return bytes(template)
        return copy.deepcopy(template)
    
    # =========================================================================
    # DER Serialization
    # =========================================================================
    
    def _serialize_der(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize DER/ASN.1 fields."""
        if field.optional and value is None and not fuzz:
            field._serialized_value = b''
            return

        clean_data = (b'' if field.optional and value is None
                      else self._build_der(field, value, False, ctx.rng))
        der_data = clean_data
        if fuzz:
            # A selected field must actually change. DER fuzz helpers include a
            # weighted "correct" choice, so retry before using a deterministic
            # tag-bit flip as a final fallback.
            for _ in range(8):
                der_data = self._build_der(field, value, True, ctx.rng)
                if der_data != clean_data:
                    break
            else:
                if der_data:
                    der_data = bytes([der_data[0] ^ der.DERTag.CONSTRUCTED]) + der_data[1:]
                else:
                    der_data = b'\x00'
            ctx.mutations.append(Mutation(
                field._path,
                f"({len(clean_data)} bytes)",
                f"({len(der_data)} bytes)",
                'der_mutation',
            ))
            ctx.record_fuzz(field)

        field._serialized_value = der_data
        ctx.write(der_data)
    
    def _build_der(self, field: Field, value: Any, fuzz: bool, rng) -> bytes:
        """Build DER-encoded data for a field."""
        ftype = field.type
        
        if ftype == FieldType.DER_SEQUENCE:
            children_data = []
            for child in field.children:
                if child.optional and not self._child_is_present(value, child):
                    continue
                child_value = self._get_child_value(value, child.name, child.default)
                children_data.append(self._build_der(child, child_value, fuzz, rng))
            if fuzz:
                children_data, _ = der.DERFuzzer.fuzz_structure(children_data, rng)
            return der.encode_der_sequence(children_data, fuzz, rng)
        
        elif ftype == FieldType.DER_SET:
            children_data = []
            for child in field.children:
                if child.optional and not self._child_is_present(value, child):
                    continue
                child_value = self._get_child_value(value, child.name, child.default)
                children_data.append(self._build_der(child, child_value, fuzz, rng))
            if fuzz:
                children_data, _ = der.DERFuzzer.fuzz_structure(children_data, rng)
            return der.encode_der_set(children_data, fuzz, rng)
        
        elif ftype == FieldType.DER_INTEGER:
            if value is None:
                value = 0
            if fuzz:
                content, _ = der.fuzz_der_integer(value, rng)
                return der.wrap_der(der.DERTag.INTEGER, content, fuzz, rng)
            return der.wrap_der(der.DERTag.INTEGER, der.encode_der_integer(value), False)
        
        elif ftype == FieldType.DER_OCTET_STRING:
            if value is None:
                value = b''
            if isinstance(value, str):
                value = value.encode('utf-8')
            elif isinstance(value, (bytes, bytearray, memoryview)):
                value = bytes(value)
            else:
                raise TypeError(f"DER OCTET STRING {field.name!r} requires bytes")
            if fuzz:
                fuzzed, _ = get_fuzz_buffer(len(value), rng=rng)
                return der.encode_der_octet_string(fuzzed, fuzz, rng)
            return der.encode_der_octet_string(value, False)
        
        elif ftype == FieldType.DER_BIT_STRING:
            if value is None:
                value = b''
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise TypeError(f"DER BIT STRING {field.name!r} requires bytes")
            value = bytes(value)
            return der.encode_der_bit_string(value, 0, fuzz, rng)
        
        elif ftype == FieldType.DER_OID:
            if value is None:
                value = b''
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise TypeError(f"DER OID {field.name!r} requires encoded bytes")
            value = bytes(value)
            if fuzz:
                fuzzed, _ = der.fuzz_der_oid(value, rng)
                return der.wrap_der(der.DERTag.OID, fuzzed, fuzz, rng)
            return der.wrap_der(der.DERTag.OID, value, False)
        
        elif ftype == FieldType.DER_BOOLEAN:
            if value is None:
                value = False
            return der.encode_der_boolean(value, fuzz, rng)
        
        elif ftype == FieldType.DER_NULL:
            return der.encode_der_null()
        
        elif ftype == FieldType.DER_ENUMERATED:
            if value is None:
                value = 0
            return der.encode_der_enumerated(value, fuzz, rng)
        
        elif ftype in (FieldType.DER_UTF8_STRING, FieldType.DER_PRINTABLE_STRING, 
                       FieldType.DER_IA5_STRING):
            if value is None:
                value = ''
            return der.encode_der_string(value, ftype, fuzz, rng)
        
        elif ftype in (FieldType.DER_UTC_TIME, FieldType.DER_GENERALIZED_TIME):
            if value is None:
                value = ('250101000000Z' if ftype == FieldType.DER_UTC_TIME
                         else '20250101000000Z')
            return der.encode_der_time(value, ftype, fuzz, rng)
        
        elif ftype == FieldType.DER_CONTEXT:
            content = self._build_der_tagged_content(field, value, fuzz, rng)
            return der.encode_der_context(
                field.tag, content, field.implicit,
                constructed=field.constructed, fuzz=fuzz, rng=rng,
            )
        
        elif ftype == FieldType.DER_APPLICATION:
            content = self._build_der_tagged_content(field, value, fuzz, rng)
            return der.encode_der_application(
                field.tag, content, constructed=field.constructed, fuzz=fuzz, rng=rng,
            )
        
        elif ftype == FieldType.DER_PRIVATE:
            content = self._build_der_tagged_content(field, value, fuzz, rng)
            return der.encode_der_private(
                field.tag, content, constructed=field.constructed, fuzz=fuzz, rng=rng,
            )
        
        elif ftype == FieldType.DER_ANY:
            if value is None:
                value = b''
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise TypeError(f"DER ANY {field.name!r} requires encoded bytes")
            return bytes(value)
        
        else:
            raise ValueError(f"Unknown DER type: {ftype}")

    def _build_der_tagged_content(self, field: Field, value: Any,
                                  fuzz: bool, rng) -> bytes:
        """Build the content octets for context/application/private tags."""
        if not field.children:
            if value is None:
                return b''
            if isinstance(value, str):
                return value.encode('utf-8')
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            raise TypeError(f"tagged DER field {field.name!r} requires bytes or children")

        children_data = []
        for child in field.children:
            if child.optional and not self._child_is_present(value, child):
                continue
            child_value = self._get_child_value(value, child.name, child.default)
            children_data.append(self._build_der(child, child_value, fuzz, rng))

        # Implicit tagging replaces one underlying TLV's tag and length. When
        # callers describe the underlying value as one child, retain only its
        # content octets. Multiple children already describe content octets.
        if field.implicit and len(children_data) == 1:
            return self._strip_der_tlv(children_data[0])
        return b''.join(children_data)

    @staticmethod
    def _strip_der_tlv(encoded: bytes) -> bytes:
        """Return DER content octets without assuming a two-byte TLV header."""
        if len(encoded) < 2:
            raise ValueError("cannot implicitly tag an incomplete DER value")
        index = 1
        if encoded[0] & 0x1f == 0x1f:
            while index < len(encoded):
                tag_byte = encoded[index]
                index += 1
                if not tag_byte & 0x80:
                    break
            else:
                raise ValueError("unterminated DER high-tag-number form")
        if index >= len(encoded):
            raise ValueError("missing DER length")
        first_length = encoded[index]
        index += 1
        if first_length == 0x80:
            return encoded[index:]
        if first_length & 0x80:
            width = first_length & 0x7f
            if width == 0 or index + width > len(encoded):
                raise ValueError("invalid DER long-form length")
            length = int.from_bytes(encoded[index:index + width], 'big')
            index += width
        else:
            length = first_length
        return encoded[index:index + length]

    @staticmethod
    def _child_is_present(parent_value: Any, child: Field) -> bool:
        if isinstance(parent_value, dict):
            if child.name in parent_value:
                return parent_value[child.name] is not None
            return child.default is not None
        if parent_value is not None and hasattr(parent_value, child.name):
            return getattr(parent_value, child.name) is not None
        return child.default is not None
    
    def _get_child_value(self, parent_value: Any, child_name: str, default: Any) -> Any:
        """Get a child field's value from parent value."""
        if parent_value is None:
            return default
        if isinstance(parent_value, dict):
            return parent_value.get(child_name, default)
        if hasattr(parent_value, child_name):
            return getattr(parent_value, child_name)
        return default
    
    # =========================================================================
    # NDR Serialization
    # =========================================================================
    
    def _serialize_ndr(self, field: Field, value: Any, ctx: SerializerContext, fuzz: bool):
        """Serialize NDR (DCE-RPC) fields."""
        if value is None:
            value = []
        raw_bytes = bytes(value) if isinstance(value, (bytes, bytearray)) else None
        elements = list(value)
        actual_count = self._ndr_reference(field.actual_field, len(elements), field, ctx)
        offset = self._ndr_reference(field.offset_field, field.ndr_offset, field, ctx)
        default_max = max(len(elements) + offset, actual_count + offset)
        if field.max_count is not None:
            default_max = field.max_count
        max_count = self._ndr_reference(field.conformant_field, default_max, field, ctx)

        for label, number in (
            ('max_count', max_count), ('offset', offset), ('actual_count', actual_count)
        ):
            if not isinstance(number, int) or number < 0 or number > 0xffffffff:
                raise ValueError(f"invalid NDR {label} {number!r} for {field._path!r}")

        original_headers = (max_count, offset, actual_count)
        strategy = None
        if fuzz:
            labels = ['max_count'] if field.type == FieldType.NDR_CONFORMANT else ['offset', 'actual_count']
            if field.type == FieldType.NDR_CONFORMANT_VARYING:
                labels.insert(0, 'max_count')
            label = ctx.rng.choice(labels)
            current = {'max_count': max_count, 'offset': offset, 'actual_count': actual_count}[label]
            choices = [candidate for candidate in COUNT_VALUES if candidate != current]
            replacement = ctx.rng.choice(choices or [current ^ 1])
            if label == 'max_count':
                max_count = replacement
            elif label == 'offset':
                offset = replacement
            else:
                actual_count = replacement
            strategy = f'ndr_{label}'

        if field.type == FieldType.NDR_CONFORMANT:
            ctx.write(struct.pack('<I', max_count))
            header_size = 4
        elif field.type == FieldType.NDR_VARYING:
            ctx.write(struct.pack('<II', offset, actual_count))
            header_size = 8
        elif field.type == FieldType.NDR_CONFORMANT_VARYING:
            ctx.write(struct.pack('<III', max_count, offset, actual_count))
            header_size = 12
        else:
            raise ValueError(f"Unknown NDR type: {field.type}")

        if raw_bytes is not None and field.element is None and not field.element_size:
            ctx.write(raw_bytes)
        else:
            self._serialize_ndr_elements(field, elements, ctx)
        field._serialized_value = value
        if strategy:
            fuzzed_headers = (max_count, offset, actual_count)
            ctx.mutations.append(Mutation(
                field._path, original_headers, fuzzed_headers, strategy,
                field._offset, header_size,
            ))
            ctx.record_fuzz(field)

    def _ndr_reference(self, reference: str, default: int,
                       field: Field, ctx: SerializerContext) -> int:
        if not reference:
            return default
        value = ctx.get_field_value(reference, field._scope)
        if value is None:
            raise ValueError(
                f"NDR reference {reference!r} for {field._path!r} "
                "must name an earlier integer field"
            )
        return value

    def _serialize_ndr_elements(self, field: Field, elements: List[Any],
                                ctx: SerializerContext):
        for index, elem in enumerate(elements):
            if field.element_size:
                if isinstance(elem, int):
                    mask = (1 << (field.element_size * 8)) - 1
                    ctx.write((elem & mask).to_bytes(field.element_size, 'little'))
                else:
                    ctx.write(bytes(elem)[:field.element_size].ljust(field.element_size, b'\x00'))
            elif isinstance(field.element, type) and issubclass(field.element, Packet):
                packet = elem if isinstance(elem, Packet) else field.element(elem if isinstance(elem, dict) else {})
                self.serialize(packet, ctx, scope=f"{field.name}[{index}]")
            elif isinstance(field.element, FieldType):
                temp = Field(f"{field.name}[{index}]", field.element, elem, fuzz=False)
                self._serialize_field(temp, ctx)
            elif isinstance(elem, int):
                ctx.write(struct.pack('<I', elem & 0xffffffff))
            elif isinstance(elem, (bytes, bytearray)):
                ctx.write(bytes(elem))
            else:
                raise TypeError(f"unsupported NDR element {elem!r} for {field._path!r}")
    
    # =========================================================================
    # Fixup Resolution
    # =========================================================================
    
    def _apply_fixups(self, ctx: SerializerContext, start: int = 0):
        """Apply all pending fixups for LENGTH, COUNT, OFFSET fields."""
        for fixup_type, position, field, scope in ctx.fixups[start:]:
            if fixup_type == 'length':
                self._fixup_length(position, field, ctx, scope)
            elif fixup_type == 'count':
                self._fixup_count(position, field, ctx, scope)
            elif fixup_type == 'offset':
                self._fixup_offset(position, field, ctx, scope)
    
    def _fixup_length(self, position: int, field: Field,
                      ctx: SerializerContext, scope: str):
        """Fix up a LENGTH field."""
        target_pos = ctx.get_field_position(field.target, scope)
        if target_pos is None:
            raise ValueError(f"LENGTH target {field.target!r} not found for {field._path!r}")
        
        target_offset, target_size = target_pos
        length = target_size
        
        if field.includes_self:
            length += FIELD_TYPE_SIZES.get(field.size_type, 4)
        
        # Apply length mismatch fuzzing
        if hasattr(field, '_fuzz_length') and field._fuzz_length:
            original = length
            max_value = self._max_for_size_type(field.size_type)
            delta = 1
            for _ in range(8):
                delta = ctx.rng.choice(LENGTH_DELTAS)
                length = max(0, min(max_value, original + delta))
                if length != original:
                    break
            if length == original:
                length = original - 1 if original else 1
                delta = length - original
            ctx.mutations.append(Mutation(
                field._path, original, length,
                'length_mismatch_short' if delta < 0 else 'length_mismatch_long',
                position, FIELD_TYPE_SIZES.get(field.size_type, 4),
            ))
        
        # Write the length value
        self._write_int_at(ctx, position, length, field.size_type)
        field._serialized_value = length
        ctx.record_value(field._path, length)
    
    def _fixup_count(self, position: int, field: Field,
                     ctx: SerializerContext, scope: str):
        """Fix up a COUNT field."""
        count = ctx.get_array_count(field.target, scope)
        if count is None:
            raise ValueError(f"COUNT target {field.target!r} not found for {field._path!r}")
        
        # Apply count mismatch fuzzing
        if hasattr(field, '_fuzz_count') and field._fuzz_count:
            original = count
            strategy = ctx.rng.choice(['overflow', 'underflow', 'boundary', 'zero'])
            if strategy == 'overflow':
                count = ctx.rng.choice([c for c in COUNT_VALUES if c > original] or [65535])
            elif strategy == 'underflow':
                count = max(0, original - ctx.rng.randint(1, max(1, original)))
            elif strategy == 'boundary':
                choices = [candidate for candidate in COUNT_VALUES if candidate != original]
                count = ctx.rng.choice(choices or [original ^ 1])
            elif strategy == 'zero':
                count = 0
            count = max(0, min(self._max_for_size_type(field.size_type), count))
            if count == original:
                count = original - 1 if original else 1
                strategy = 'off_by_one'
            ctx.mutations.append(Mutation(
                field._path, original, count, f'count_{strategy}',
                position, FIELD_TYPE_SIZES.get(field.size_type, 4),
            ))
        
        self._write_int_at(ctx, position, count, field.size_type)
        field._serialized_value = count
        ctx.record_value(field._path, count)
    
    def _fixup_offset(self, position: int, field: Field,
                      ctx: SerializerContext, scope: str):
        """Fix up an OFFSET field."""
        target_pos = ctx.get_field_position(field.target, scope)
        if target_pos is None:
            raise ValueError(f"OFFSET target {field.target!r} not found for {field._path!r}")
        
        target_offset, _ = target_pos
        
        # Calculate offset relative to base
        if field.base:
            base_pos = ctx.get_marker(field.base, scope)
            if base_pos is None:
                raise ValueError(f"OFFSET base {field.base!r} not found for {field._path!r}")
            offset = target_offset - base_pos
        elif field.relative:
            offset = target_offset - position
        else:
            offset = target_offset
        
        offset += field.skip
        
        # Apply offset fuzzing
        if hasattr(field, '_fuzz_offset') and field._fuzz_offset:
            original = offset
            corruption = ctx.rng.choice(OFFSET_CORRUPTIONS)
            if isinstance(corruption, int) and corruption < 0:
                offset = max(0, offset + corruption)
            else:
                offset = corruption
            offset = max(0, min(self._max_for_size_type(field.size_type), offset))
            if offset == original:
                offset = original - 1 if original else 1
            ctx.mutations.append(Mutation(
                field._path, original, offset, 'offset_corrupt',
                position, FIELD_TYPE_SIZES.get(field.size_type, 4),
            ))
        
        self._write_int_at(ctx, position, offset, field.size_type)
        field._serialized_value = offset
        ctx.record_value(field._path, offset)
    
    def _write_int_at(self, ctx: SerializerContext, position: int, value: int, 
                      size_type: FieldType):
        """Write an integer at a specific position."""
        size = FIELD_TYPE_SIZES.get(size_type, 4)
        
        if size_type in (FieldType.WORD_BE, FieldType.DWORD_BE, FieldType.QWORD_BE):
            fmt = {2: '>H', 4: '>I', 8: '>Q'}[size]
        else:
            fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}[size]
        
        max_val = self._max_for_size_type(size_type)
        if not isinstance(value, int) or not 0 <= value <= max_val:
            raise OverflowError(
                f"value {value!r} does not fit {size_type.name} fixup field"
            )
        
        data = struct.pack(fmt, value)
        ctx.write_at(position, data)

    @staticmethod
    def _max_for_size_type(size_type: FieldType) -> int:
        size = FIELD_TYPE_SIZES.get(size_type, 4)
        return (1 << (size * 8)) - 1

"""
OffByWon Framework - Field and Packet Definitions

Classes for declaratively defining packet structures.
"""

import copy
from typing import List, Any, Optional, Union, Dict

from .types import FieldType


class Field:
    """
    Field definition for packet structures.
    
    A Field describes a single element in a packet: its name, type,
    default value, and relationship to other fields.
    """
    
    def __init__(self, name: str, ftype: FieldType, default: Any = None, **kwargs):
        """
        Initialize a field definition.
        
        Args:
            name: Field name (used for reference and output)
            ftype: Field type from FieldType enum
            default: Default value (type depends on ftype)
            **kwargs: Type-specific options
        
        Common kwargs:
            fuzz: bool - Whether to fuzz this field (default True)
            
        For LENGTH, COUNT:
            target: str - Name of field this describes
            size_type: FieldType - How to serialize the length (WORD, DWORD, etc.)
            includes_self: bool - Whether length includes this field itself
            
        For OFFSET:
            target: str - Field this points to
            base: str - Reference point for offset calculation (marker name)
            relative: bool - Offset is relative to current position
            skip: int - Additional bytes to skip
            size_type: FieldType - How to serialize the offset
            
        For BYTES:
            size: int - Fixed size (None for variable)
            size_from: str - Field name that provides the size
            
        For STRING:
            encoding: str - Text encoding (default 'utf-16-le')
            null_terminated: bool - Whether to add null terminator
            size: int - Fixed size (pad/truncate to this)
            size_from: str - Field name that provides the size
            
        For ARRAY:
            element: FieldType or Type[Packet] - Element type
            element_size: int - Fixed element size (for simple types)
            count_from: str - Field name that provides count
            
        For STRUCT:
            element: Type[Packet] - Nested packet class
            
        For PADDING:
            align: int - Alignment boundary (default 4)
            relative_to: str - Reference point for alignment
            
        For DER types:
            tag: int - Tag number (for CONTEXT, APPLICATION, PRIVATE)
            implicit: bool - Implicit vs explicit tagging
            children: List[Field] - Child fields for constructed types
            optional: bool - Whether this field is optional
            
        For NDR types:
            max_count: int - Maximum element count
            conformant_field: str - Field with max count
            offset_field: str - Field with offset
            actual_field: str - Field with actual count
        """
        self.name = name
        self.type = ftype
        self.default = default
        
        # Fuzzing control
        self.fuzz = kwargs.get('fuzz', True)
        
        # For LENGTH, COUNT, OFFSET
        self.target = kwargs.get('target')
        self.size_type = kwargs.get('size_type', self._default_size_type(ftype))
        self.includes_self = kwargs.get('includes_self', False)
        
        # For OFFSET
        self.base = kwargs.get('base')
        self.relative = kwargs.get('relative', False)
        self.skip = kwargs.get('skip', 0)
        
        # For BYTES, STRING
        self.size = kwargs.get('size')
        self.size_from = kwargs.get('size_from')
        self.encoding = kwargs.get('encoding', 'utf-16-le')
        self.null_terminated = kwargs.get('null_terminated', False)
        
        # For ARRAY
        self.element = kwargs.get('element')
        self.element_size = kwargs.get('element_size')
        self.count_from = kwargs.get('count_from')

        # For UNION
        self.selector = kwargs.get('selector')
        self.choices = kwargs.get('choices', {})
        
        # For PADDING
        self.align = kwargs.get('align', 4)
        self.relative_to = kwargs.get('relative_to')
        
        # For DER types
        self.tag = kwargs.get('tag')
        self.implicit = kwargs.get('implicit', False)
        self.children = kwargs.get('children', [])
        self.optional = kwargs.get('optional', False)
        self.constructed = kwargs.get('constructed', bool(self.children))
        
        # For NDR
        self.max_count = kwargs.get('max_count')
        self.conformant_field = kwargs.get('conformant_field')
        self.offset_field = kwargs.get('offset_field')
        self.actual_field = kwargs.get('actual_field')
        self.ndr_offset = kwargs.get('ndr_offset', 0)
        
        # Marker support
        self.marker = kwargs.get('marker', False)
        
        # Runtime value (set during build)
        self._value = None
        self._value_set = False
        self._offset = None  # Byte offset in serialized packet
        self._size = None    # Serialized size

        self._validate()

    def _validate(self):
        """Reject invalid declarations before they can emit ambiguous bytes."""
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("field name must be a non-empty string")
        if not isinstance(self.type, FieldType):
            raise TypeError(f"field {self.name!r} has invalid type {self.type!r}")
        if self.size is not None and self.size < 0:
            raise ValueError(f"field {self.name!r} size cannot be negative")
        if self.size is not None and self.size_from is not None:
            raise ValueError(f"field {self.name!r} cannot use both size= and size_from=")
        if self.element_size is not None and self.element_size <= 0:
            raise ValueError(f"field {self.name!r} element_size must be positive")
        for option_name, reference in (
            ('target', self.target), ('base', self.base),
            ('relative_to', self.relative_to), ('size_from', self.size_from),
            ('count_from', self.count_from), ('selector', self.selector),
            ('conformant_field', self.conformant_field),
            ('offset_field', self.offset_field), ('actual_field', self.actual_field),
        ):
            if reference is not None and (
                    not isinstance(reference, str) or not reference):
                raise ValueError(
                    f"field {self.name!r} {option_name}= must be a non-empty field name"
                )
        if self.type in (FieldType.LENGTH, FieldType.COUNT, FieldType.OFFSET):
            if not self.target:
                raise ValueError(f"{self.type.name} field {self.name!r} requires target=")
            if self.size_type not in (
                    FieldType.BYTE, FieldType.WORD, FieldType.DWORD, FieldType.QWORD,
                    FieldType.WORD_BE, FieldType.DWORD_BE, FieldType.QWORD_BE):
                raise ValueError(
                    f"{self.type.name} field {self.name!r} requires a fixed-width size_type"
                )
        if self.type == FieldType.PADDING and self.align <= 0:
            raise ValueError(f"PADDING field {self.name!r} align must be positive")
        if self.type in (FieldType.DER_CONTEXT, FieldType.DER_APPLICATION, FieldType.DER_PRIVATE):
            if not isinstance(self.tag, int) or not 0 <= self.tag <= 30:
                raise ValueError(f"{self.type.name} field {self.name!r} requires tag=0..30")
        if self.type == FieldType.STRUCT:
            if not (isinstance(self.element, type) and issubclass(self.element, Packet)):
                raise ValueError(f"STRUCT field {self.name!r} requires a Packet class in element=")
        if self.type == FieldType.ARRAY:
            if self.element is None and self.element_size is None:
                raise ValueError(
                    f"ARRAY field {self.name!r} requires element= or element_size="
                )
            valid_element = (
                self.element is None
                or isinstance(self.element, FieldType)
                or (isinstance(self.element, type) and issubclass(self.element, Packet))
            )
            if not valid_element:
                raise TypeError(
                    f"ARRAY field {self.name!r} element must be a FieldType or Packet class"
                )
            if (self.element_size is not None and isinstance(self.element, type)
                    and issubclass(self.element, Packet)):
                raise ValueError(
                    f"ARRAY field {self.name!r} cannot combine Packet element= with element_size="
                )
        if not isinstance(self.children, list) or not all(
                isinstance(child, Field) for child in self.children):
            raise TypeError(f"field {self.name!r} children must be a list of Field objects")
        if not isinstance(self.choices, dict):
            raise TypeError(f"UNION field {self.name!r} choices must be a dict")
        if self.type == FieldType.UNION and not self.choices and self.element is None:
            raise ValueError(f"UNION field {self.name!r} requires choices= or element=")
        if self.type in (
                FieldType.NDR_CONFORMANT, FieldType.NDR_VARYING,
                FieldType.NDR_CONFORMANT_VARYING):
            for option_name, number in (
                ('max_count', self.max_count), ('ndr_offset', self.ndr_offset),
            ):
                if number is not None and (
                        not isinstance(number, int) or not 0 <= number <= 0xffffffff):
                    raise ValueError(
                        f"NDR field {self.name!r} {option_name}= must fit an unsigned DWORD"
                    )
    
    def _default_size_type(self, ftype: FieldType) -> FieldType:
        """Get default size type for LENGTH/COUNT/OFFSET fields."""
        if ftype in (FieldType.LENGTH, FieldType.COUNT, FieldType.OFFSET):
            return FieldType.DWORD  # Safe default
        return None
    
    @property
    def value(self) -> Any:
        """Get the current value (runtime or default)."""
        return self._value if self._value_set else self.default
    
    @value.setter
    def value(self, v: Any):
        """Set the runtime value."""
        self._value = v
        self._value_set = True
    
    def clone(self) -> 'Field':
        """Create a deep copy of this field."""
        f = Field(
            self.name,
            self.type,
            copy.deepcopy(self.default),
            fuzz=self.fuzz,
            target=self.target,
            size_type=self.size_type,
            includes_self=self.includes_self,
            base=self.base,
            relative=self.relative,
            skip=self.skip,
            size=self.size,
            size_from=self.size_from,
            encoding=self.encoding,
            null_terminated=self.null_terminated,
            element=self.element,
            element_size=self.element_size,
            count_from=self.count_from,
            selector=self.selector,
            choices=dict(self.choices),
            align=self.align,
            relative_to=self.relative_to,
            tag=self.tag,
            implicit=self.implicit,
            children=[c.clone() for c in self.children],
            optional=self.optional,
            constructed=self.constructed,
            max_count=self.max_count,
            conformant_field=self.conformant_field,
            offset_field=self.offset_field,
            actual_field=self.actual_field,
            ndr_offset=self.ndr_offset,
            marker=self.marker,
        )
        f._value = copy.deepcopy(self._value)
        f._value_set = self._value_set
        return f
    
    def __repr__(self) -> str:
        return f"Field({self.name!r}, {self.type.name}, default={self.default!r})"


class Marker:
    """
    Marker for offset reference points.
    
    Insert this in a field list to create a named reference point
    that OFFSET fields can use as their base.
    """
    
    def __init__(self, name: str):
        if not isinstance(name, str) or not name:
            raise ValueError("marker name must be a non-empty string")
        self.name = name
        self._offset = None  # Set during serialization
    
    def clone(self) -> 'Marker':
        m = Marker(self.name)
        m._offset = self._offset
        return m
    
    def __repr__(self) -> str:
        return f"Marker({self.name!r})"


class PacketMeta(type):
    """Metaclass for Packet to support class-based field definitions."""
    
    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        
        # Collect fields from class and bases
        fields = []
        for base in reversed(bases):
            if hasattr(base, '_fields'):
                fields.extend(base._fields)
        
        # Add fields defined in this class
        if 'fields' in namespace:
            fields.extend(namespace['fields'])
        
        cls._fields = fields
        return cls


class Packet(metaclass=PacketMeta):
    """
    Base class for packet definitions.
    
    Define packets by subclassing and setting the `fields` class attribute:
    
        class MyPacket(Packet):
            fields = [
                Field('version', FieldType.BYTE, 1),
                Field('length', FieldType.LENGTH, target='data', size_type=FieldType.WORD),
                Field('data', FieldType.BYTES),
            ]
    
    The framework will instantiate packets and manage field values during building.
    """
    
    fields: List[Union[Field, Marker]] = []
    
    def __init__(self, values: Dict[str, Any] = None):
        """
        Create a packet instance with optional runtime values.
        
        Args:
            values: Dict mapping field names to values
        """
        self._field_instances = [
            f.clone() if isinstance(f, (Field, Marker)) else f 
            for f in self._fields
        ]
        self._markers = {}
        
        # Index fields by name
        self._field_map = {}
        for f in self._field_instances:
            if isinstance(f, Field):
                if f.name in self._field_map:
                    raise ValueError(f"duplicate field name: {f.name!r}")
                self._field_map[f.name] = f
            elif isinstance(f, Marker):
                if f.name in self._markers:
                    raise ValueError(f"duplicate marker name: {f.name!r}")
                self._markers[f.name] = f
        
        # Apply provided values
        if values:
            self.set_values(values)
    
    def set_values(self, values: Dict[str, Any]):
        """Set multiple field values at once."""
        for name, value in values.items():
            self.set_value(name, value)
    
    def set_value(self, name: str, value: Any):
        """
        Set a field value by name.
        
        Supports dotted paths for nested fields: 'header.session_id'
        """
        if '.' in name:
            parts = name.split('.', 1)
            field = self._field_map.get(parts[0])
            if field is None:
                raise KeyError(f"unknown field: {parts[0]}")
            if field.type != FieldType.STRUCT or not field.element:
                raise KeyError(f"field {parts[0]!r} is not a nested structure")
            nested = field.value
            if isinstance(nested, dict):
                nested = field.element(nested)
            elif nested is None:
                nested = field.element()
            if not isinstance(nested, Packet):
                raise TypeError(f"field {parts[0]!r} does not contain a Packet")
            field.value = nested
            nested.set_value(parts[1], value)
        else:
            field = self._field_map.get(name)
            if field is None:
                raise KeyError(f"unknown field: {name}")
            field.value = value
    
    def get_value(self, name: str) -> Any:
        """Get a field value by name (supports dotted paths)."""
        if '.' in name:
            parts = name.split('.', 1)
            field = self._field_map.get(parts[0])
            if field and field.type == FieldType.STRUCT:
                nested = field.value
                if isinstance(nested, dict) and field.element:
                    nested = field.element(nested)
                    field.value = nested
                elif nested is None and field.element:
                    nested = field.element()
                    field.value = nested
                if isinstance(nested, Packet):
                    return nested.get_value(parts[1])
            return None
        else:
            field = self._field_map.get(name)
            return field.value if field else None
    
    def get_field(self, name: str) -> Optional[Field]:
        """Get a field by name (supports dotted paths)."""
        if '.' in name:
            parts = name.split('.', 1)
            field = self._field_map.get(parts[0])
            if field and field.type == FieldType.STRUCT:
                nested = field.value
                if isinstance(nested, dict) and field.element:
                    nested = field.element(nested)
                    field.value = nested
                elif nested is None and field.element:
                    nested = field.element()
                    field.value = nested
                if isinstance(nested, Packet):
                    return nested.get_field(parts[1])
            return None
        return self._field_map.get(name)
    
    def get_marker(self, name: str) -> Optional[Marker]:
        """Get a marker by name."""
        return self._markers.get(name)
    
    def iter_fields(self) -> List[Union[Field, Marker]]:
        """Iterate over all fields and markers in order."""
        return self._field_instances
    
    def get_fuzzable_fields(self, names: List[str] = None) -> List[Field]:
        """
        Get fields that can be fuzzed.
        
        Args:
            names: Optional list of specific field names to consider
        
        Returns:
            List of Field objects with fuzz=True
        """
        result = []

        def collect_der(children):
            for child in children:
                if child.fuzz and (not names or child.name in names):
                    result.append(child)
                collect_der(child.children)

        for f in self._field_instances:
            if not isinstance(f, Field):
                continue
            if f.fuzz and (not names or f.name in names):
                result.append(f)
            
            # Recurse into nested structures, including defaults that have not
            # yet been instantiated by a dotted assignment.
            if f.type == FieldType.STRUCT and f.element:
                nested_value = f.value
                if isinstance(nested_value, Packet):
                    nested = nested_value
                else:
                    nested = f.element(nested_value if isinstance(nested_value, dict) else {})
                result.extend(nested.get_fuzzable_fields(names))
            elif (f.type == FieldType.ARRAY and isinstance(f.element, type)
                  and issubclass(f.element, Packet)):
                for item in list(f.value or []):
                    nested = item if isinstance(item, Packet) else f.element(
                        item if isinstance(item, dict) else {}
                    )
                    result.extend(nested.get_fuzzable_fields(names))
            elif f.type in (FieldType.DER_SEQUENCE, FieldType.DER_SET, 
                           FieldType.DER_CONTEXT, FieldType.DER_APPLICATION,
                           FieldType.DER_PRIVATE):
                collect_der(f.children)
        
        return result
    
    @classmethod
    def from_fields(cls, fields: List[Union[Field, Marker]], values: Dict[str, Any] = None) -> 'Packet':
        """
        Create a packet instance from a list of fields.
        
        This allows dynamic packet construction without subclassing.
        """
        instance = cls.__new__(cls)
        instance._fields = fields
        instance._field_instances = [
            f.clone() if isinstance(f, (Field, Marker)) else f 
            for f in fields
        ]
        instance._markers = {}
        instance._field_map = {}
        
        for f in instance._field_instances:
            if isinstance(f, Field):
                if f.name in instance._field_map:
                    raise ValueError(f"duplicate field name: {f.name!r}")
                instance._field_map[f.name] = f
            elif isinstance(f, Marker):
                if f.name in instance._markers:
                    raise ValueError(f"duplicate marker name: {f.name!r}")
                instance._markers[f.name] = f
        
        if values:
            instance.set_values(values)
        
        return instance
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({len(self._field_map)} fields)"

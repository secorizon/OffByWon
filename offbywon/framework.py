"""
OffByWon Framework - Main Framework Class

The central API for building and fuzzing packets.
"""

import copy
import random
from typing import Any, Dict, List, Optional, Tuple, Type, Union

from .types import (
    FieldType, FuzzMode, Mutation, ByteFlip, FuzzInfo,
    get_fuzz_integer, get_fuzz_buffer,
)
from .packet import Field, Marker, Packet
from .serializer import Serializer, SerializerContext


class Framework:
    """
    OffByWon Framework - Declarative Protocol Fuzzing
    
    The Framework class provides the main API for:
    - Building packets from declarative definitions
    - Applying various fuzzing strategies
    - Producing standardized output
    
    Usage:
        from offbywon import Framework
        from my_protocol import MyPacket
        
        fw = Framework()
        data, info = fw.build(MyPacket, mode='combined', values={'session_id': 123})
        sock.send(data)
    """

    AI_STRATEGIES = (
        FuzzMode.FIELD,
        FuzzMode.LENGTH,
        FuzzMode.ARRAY,
        FuzzMode.BYTEFLIP,
        FuzzMode.BLIND,
        FuzzMode.COMBINED,
        FuzzMode.FULL,
    )
    
    def __init__(self, verbose: bool = True, color: bool = True,
                 seed: int = None, rng=None):
        """
        Initialize the framework.
        
        Args:
            verbose: Whether to print output for each packet
            color: Whether to use ANSI colors in output
            seed: Optional seed for a reproducible sequence of builds
            rng: Optional ``random.Random``-compatible generator
        """
        if seed is not None and rng is not None:
            raise ValueError("pass either seed or rng, not both")
        if seed is not None and not isinstance(seed, int):
            raise TypeError("seed must be an int")
        self.verbose = verbose
        self.color = color
        self.packet_count = 0
        self.serializer = Serializer()
        self._rng = rng if rng is not None else random.Random(seed)
        self._ai_mode_counts = {mode: 0 for mode in self.AI_STRATEGIES}

    def choose_ai_mode(self, available_modes=None, rng=None) -> FuzzMode:
        """Choose the least-used available strategy for balanced coverage.

        Ties are randomized. Consequently every available strategy is chosen
        once before any strategy is chosen a second time. Supplying a seeded
        framework makes the tie order reproducible.
        """
        candidates = self.AI_STRATEGIES if available_modes is None else available_modes
        normalized = []
        for candidate in candidates:
            if isinstance(candidate, str):
                candidate = FuzzMode(candidate)
            elif not isinstance(candidate, FuzzMode):
                raise TypeError("AI strategies must be FuzzMode values or valid mode strings")
            if candidate in (FuzzMode.CLEAN, FuzzMode.AI):
                raise ValueError("AI strategy candidates cannot include 'clean' or 'ai'")
            if candidate not in normalized:
                normalized.append(candidate)
        if not normalized:
            raise ValueError("at least one AI strategy candidate is required")

        rng = rng if rng is not None else self._rng
        minimum = min(self._ai_mode_counts.get(mode, 0) for mode in normalized)
        least_used = [
            mode for mode in normalized
            if self._ai_mode_counts.get(mode, 0) == minimum
        ]
        selected = rng.choice(least_used)
        self._ai_mode_counts[selected] = self._ai_mode_counts.get(selected, 0) + 1
        return selected
    
    def build(self,
              packet_class: Type[Packet],
              mode: Union[str, FuzzMode] = 'clean',
              values: Dict[str, Any] = None,
              fuzz_count: int = None,
              fields: List[str] = None,
              array_expand: bool = False,
              array_max: int = 65535,
              byteflip_count: int = None,
              seed: int = None) -> Tuple[bytes, FuzzInfo]:
        """
        Build a packet with optional fuzzing.
        
        Args:
            packet_class: Packet definition class (subclass of Packet)
            mode: Fuzzing mode - one of:
                - 'clean': No fuzzing
                - 'ai': Automatically balance all applicable fuzzing strategies
                - 'field': Field-level mutations only
                - 'blind': Random byte corruption
                - 'byteflip': Targeted byte flips
                - 'combined': Field + byteflip
                - 'length': Length/count/offset mismatches
                - 'array': Array expansion/manipulation
                - 'full': All strategies combined
            values: Runtime values dict, e.g., {'field_name': value}
                    Supports dotted paths: {'header.session_id': 123}
            fuzz_count: Max fields to fuzz (AI default: 1; other modes: auto 1-5)
            fields: Specific field names to target (None = random selection)
            array_expand: If True, expand arrays to match fuzzed COUNT fields
            array_max: Maximum array size when expanding (default 65535)
            byteflip_count: Number of byte flips to apply (AI default: 1;
                            other modes: auto 1-5)
            seed: Reproduce one exact build, including field selection
        
        Returns:
            Tuple of (packet_bytes, FuzzInfo)
            
        Example:
            >>> fw = Framework()
            >>> data, info = fw.build(SMBNegotiate, mode='field')
            >>> print(f"Fuzzed {len(info.mutations)} fields")
        """
        self.packet_count += 1
        
        # Normalize mode
        if isinstance(mode, str):
            mode = FuzzMode(mode)
        elif not isinstance(mode, FuzzMode):
            raise TypeError("mode must be a FuzzMode or valid mode string")
        requested_mode = mode
        if not (isinstance(packet_class, type) and issubclass(packet_class, Packet)):
            raise TypeError("packet_class must be a Packet subclass")
        if values is not None and not isinstance(values, dict):
            raise TypeError("values must be a dict")
        if fields is not None and (
                isinstance(fields, (str, bytes)) or not isinstance(fields, (list, tuple))):
            raise TypeError("fields must be a list or tuple of field names")
        if fields is not None and not all(isinstance(name, str) for name in fields):
            raise TypeError("field names must be strings")
        if seed is not None and not isinstance(seed, int):
            raise TypeError("seed must be an int")
        if fuzz_count is not None and not isinstance(fuzz_count, int):
            raise TypeError("fuzz_count must be an int")
        if byteflip_count is not None and not isinstance(byteflip_count, int):
            raise TypeError("byteflip_count must be an int")
        if not isinstance(array_max, int):
            raise TypeError("array_max must be an int")
        if fuzz_count is not None and fuzz_count < 0:
            raise ValueError("fuzz_count cannot be negative")
        if byteflip_count is not None and byteflip_count < 0:
            raise ValueError("byteflip_count cannot be negative")
        if array_max < 0:
            raise ValueError("array_max cannot be negative")

        case_seed = seed if seed is not None else self._rng.getrandbits(64)
        case_rng = random.Random(case_seed)
        
        # Create packet instance with values
        packet = packet_class(copy.deepcopy(values or {}))

        # AI mode balances only strategies that can do useful work for this
        # packet. Raw modes are always applicable; structured modes require at
        # least one eligible field. Explicit fields further constrain which
        # structured strategies may be selected.
        if requested_mode == FuzzMode.AI:
            mode = self.choose_ai_mode(
                self._applicable_ai_modes(
                    packet,
                    fields,
                    fuzz_count=fuzz_count,
                    byteflip_count=byteflip_count,
                ),
                rng=case_rng,
            )
            if fuzz_count is None:
                fuzz_count = 1
            if byteflip_count is None:
                byteflip_count = 1
        
        # Pre-select fields to fuzz when fuzz_count is set but no specific fields given
        # Skip field selection for modes that only do raw byte mutations
        target_fields = list(fields) if fields is not None else None
        field_fuzz_modes = (FuzzMode.FIELD, FuzzMode.COMBINED, FuzzMode.LENGTH, FuzzMode.ARRAY, FuzzMode.FULL)
        selected_count = fuzz_count
        if mode in field_fuzz_modes:
            fuzzable = self._collect_fuzzable_fields(
                packet, mode, explicit=fields is not None,
            )
            if fields is not None:
                unknown = [
                    requested for requested in fields
                    if not any(
                        SerializerContext._target_matches(
                            requested, candidate, candidate.rsplit('.', 1)[-1]
                        )
                        for candidate in fuzzable
                    )
                ]
                if unknown:
                    raise ValueError(
                        "unknown or ineligible fuzz field(s): " + ', '.join(unknown)
                    )
            else:
                if fuzz_count is None:
                    selected_count = case_rng.randint(1, min(5, len(fuzzable))) if fuzzable else 0
                else:
                    selected_count = min(fuzz_count, len(fuzzable))
                target_fields = case_rng.sample(fuzzable, selected_count) if selected_count else []
        
        # Create serialization context
        ctx = SerializerContext(mode, case_rng)
        ctx.array_expand = array_expand
        ctx.array_max = array_max
        ctx.fuzz_count = selected_count
        ctx.target_fields = target_fields
        ctx.explicit_mode_override = fields is not None
        
        # Build clean version for size comparison
        clean_ctx = SerializerContext(FuzzMode.CLEAN, random.Random(case_seed))
        clean_packet = packet_class(copy.deepcopy(values or {}))
        self.serializer.serialize(clean_packet, clean_ctx)
        original_size = len(clean_ctx.get_bytes())
        
        # Serialize with fuzzing
        self.serializer.serialize(packet, ctx)
        data = ctx.get_bytes()
        
        # Apply byteflip if needed
        byteflips = []
        if mode in (FuzzMode.BYTEFLIP, FuzzMode.COMBINED, FuzzMode.FULL):
            data, byteflips = self._apply_byteflips(data, byteflip_count, case_rng)
        
        # Apply blind corruption if needed
        if mode in (FuzzMode.BLIND, FuzzMode.FULL):
            data, blind_mutation = self._apply_blind_corruption(
                data, case_rng, return_mutation=True,
            )
            if blind_mutation is not None:
                ctx.mutations.append(blind_mutation)
        
        # Build info
        info = FuzzInfo(
            mode=mode,
            mutations=ctx.mutations,
            byteflips=byteflips,
            array_expansions=ctx.array_expansions,
            length_mismatches=[
                m.field for m in ctx.mutations
                if ('mismatch' in m.strategy or m.strategy.startswith('count_')
                    or (mode == FuzzMode.LENGTH and m.field != '<packet>'))
            ],
            original_size=original_size,
            fuzzed_size=len(data),
            seed=case_seed,
            requested_mode=(requested_mode if requested_mode == FuzzMode.AI else None),
        )
        
        # Print standardized output
        if self.verbose:
            self._print_output(packet_class.__name__, info, data)
        
        return data, info

    def _applicable_ai_modes(self, packet: Packet,
                             fields: List[str] = None,
                             fuzz_count: int = None,
                             byteflip_count: int = None) -> List[FuzzMode]:
        """Return strategies that can mutate this packet and field selection."""
        explicit = fields is not None

        def eligible_fields(mode: FuzzMode) -> List[str]:
            return self._collect_fuzzable_fields(packet, mode, explicit=explicit)

        def supports_requested(mode: FuzzMode) -> bool:
            candidates = eligible_fields(mode)
            if fields is None:
                return bool(candidates)
            return all(any(
                SerializerContext._target_matches(
                    requested, candidate, candidate.rsplit('.', 1)[-1]
                )
                for candidate in candidates
            ) for requested in fields)

        # Validate explicit names once against normal structured fuzzing so a
        # typo cannot be hidden by a raw strategy selected on that round.
        if fields is not None:
            normal_fields = eligible_fields(FuzzMode.FIELD)
            unknown = [
                requested for requested in fields
                if not any(
                    SerializerContext._target_matches(
                        requested, candidate, candidate.rsplit('.', 1)[-1]
                    )
                    for candidate in normal_fields
                )
            ]
            if unknown:
                raise ValueError(
                    "unknown or ineligible fuzz field(s): " + ', '.join(unknown)
                )

        structured_enabled = fuzz_count != 0 and fields != []
        byteflip_enabled = byteflip_count != 0

        modes = []
        if structured_enabled and supports_requested(FuzzMode.FIELD):
            modes.append(FuzzMode.FIELD)
        if structured_enabled and supports_requested(FuzzMode.LENGTH):
            modes.append(FuzzMode.LENGTH)
        if structured_enabled and supports_requested(FuzzMode.ARRAY):
            modes.append(FuzzMode.ARRAY)
        if byteflip_enabled:
            modes.append(FuzzMode.BYTEFLIP)
        modes.append(FuzzMode.BLIND)
        if (structured_enabled and byteflip_enabled
                and supports_requested(FuzzMode.COMBINED)):
            modes.append(FuzzMode.COMBINED)
        # FULL remains distinct when it can combine blind corruption with at
        # least one enabled structured or byteflip component.
        if (byteflip_enabled or (structured_enabled and supports_requested(FuzzMode.FULL))):
            modes.append(FuzzMode.FULL)
        return modes
    
    def build_clean(self, packet_class: Type[Packet], 
                    values: Dict[str, Any] = None) -> bytes:
        """
        Build a clean (unfuzzed) packet.
        
        Convenience method equivalent to build(..., mode='clean').
        
        Args:
            packet_class: Packet definition class
            values: Runtime values
        
        Returns:
            Packet bytes (no FuzzInfo since nothing was fuzzed)
        """
        verbose = self.verbose
        try:
            self.verbose = False
            data, _ = self.build(packet_class, mode='clean', values=values)
            return data
        finally:
            self.verbose = verbose
    
    def _collect_fuzzable_fields(self, packet: Packet, mode: FuzzMode,
                                 prefix: str = '', explicit: bool = False) -> List[str]:
        """
        Collect all fuzzable field names from a packet.
        
        Args:
            packet: Packet instance to inspect
        
        Returns:
            List of field names that can be fuzzed
        """
        fuzzable = []
        for field in packet.iter_fields():
            if not isinstance(field, Field):
                continue
            path = f"{prefix}.{field.name}" if prefix else field.name
            eligible = SerializerContext.type_is_fuzzable(mode, field.type)
            if (not eligible and explicit and mode in (FuzzMode.LENGTH, FuzzMode.ARRAY)
                    and SerializerContext.type_is_numeric(field.type)):
                eligible = True
            if field.fuzz and eligible:
                fuzzable.append(path)

            if field.type == FieldType.STRUCT and field.element:
                nested_value = field.value
                if isinstance(nested_value, Packet):
                    nested = nested_value
                else:
                    nested = field.element(nested_value if isinstance(nested_value, dict) else {})
                fuzzable.extend(self._collect_fuzzable_fields(
                    nested, mode, path, explicit,
                ))
            elif (field.type == FieldType.ARRAY and isinstance(field.element, type)
                  and issubclass(field.element, Packet)):
                values = list(field.value or [])
                if values:
                    for index, item in enumerate(values):
                        nested = item if isinstance(item, Packet) else field.element(
                            item if isinstance(item, dict) else {}
                        )
                        fuzzable.extend(self._collect_fuzzable_fields(
                            nested, mode, f"{path}[{index}]", explicit,
                        ))
        return fuzzable
    
    def _apply_byteflips(self, data: bytes, count: int = None,
                         rng=None) -> Tuple[bytes, List[ByteFlip]]:
        """Apply byte-level flips to serialized data."""
        if len(data) == 0:
            return data, []
        rng = rng if rng is not None else self._rng
        
        data = bytearray(data)
        flips = []
        
        if count is None:
            count = rng.randint(1, min(5, len(data)))
        
        positions = rng.sample(range(len(data)), min(count, len(data)))
        
        for pos in positions:
            original = data[pos]
            
            # Choose flip strategy
            strategy = rng.choice(['invert', 'zero', 'ones', 'boundary', 'random'])
            
            if strategy == 'invert':
                fuzzed = original ^ 0xFF
            elif strategy == 'zero':
                fuzzed = 0x00
            elif strategy == 'ones':
                fuzzed = 0xFF
            elif strategy == 'boundary':
                fuzzed = rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
            else:
                fuzzed = rng.randint(0, 255)
            if fuzzed == original:
                fuzzed = original ^ 0xff
            
            data[pos] = fuzzed
            flips.append(ByteFlip(pos, original, fuzzed))
        
        return bytes(data), flips
    
    def _apply_blind_corruption(self, data: bytes, rng=None,
                                return_mutation: bool = False):
        """Apply random corruption (blind fuzzing)."""
        rng = rng if rng is not None else self._rng
        if len(data) == 0:
            result = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 32)))
            mutation = Mutation(
                '<packet>', '(0 bytes)', f"({len(result)} bytes)",
                'blind_extend', 0, len(result),
            )
            return (result, mutation) if return_mutation else result
        
        data = bytearray(data)
        original_size = len(data)
        
        # Random corruption strategies
        strategies = ['truncate', 'extend', 'corrupt_region']
        if len(data) >= 2:
            strategies.append('shuffle')
        strategy = rng.choice(strategies)
        
        if strategy == 'truncate':
            cut_point = rng.randint(0, len(data) - 1)
            removed = len(data) - cut_point
            data = data[:cut_point]
            offset, size = cut_point, removed
        
        elif strategy == 'extend':
            extra = bytes(rng.randint(0, 255) for _ in range(rng.randint(10, 1000)))
            offset, size = len(data), len(extra)
            data = data + extra
        
        elif strategy == 'corrupt_region':
            start = rng.randint(0, len(data) - 1)
            length = rng.randint(1, min(100, len(data) - start))
            for i in range(start, start + length):
                replacement = rng.randint(0, 255)
                data[i] = replacement if replacement != data[i] else data[i] ^ 0xff
            offset, size = start, length
        
        elif strategy == 'shuffle':
            # Shuffle a region
            start = rng.randint(0, len(data) - 2)
            length = rng.randint(2, min(50, len(data) - start))
            region = list(data[start:start + length])
            original_region = region[:]
            rng.shuffle(region)
            if region == original_region:
                region[0] ^= 0xff
            data[start:start + length] = region
            offset, size = start, length
        
        result = bytes(data)
        mutation = Mutation(
            '<packet>', f"({original_size} bytes)", f"({len(result)} bytes)",
            f'blind_{strategy}', offset, size,
        )
        return (result, mutation) if return_mutation else result
    
    def _print_output(self, packet_name: str, info: FuzzInfo, data: bytes):
        """Print standardized OffByWon output."""
        # Colors
        if self.color:
            CYAN = '\033[96m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            BOLD = '\033[1m'
            RESET = '\033[0m'
            DIM = '\033[2m'
        else:
            CYAN = GREEN = YELLOW = RED = BOLD = RESET = DIM = ''
        
        print()
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}[OffByWon]{RESET} {BOLD}PACKET #{self.packet_count}{RESET}")
        mode_label = info.mode.value
        if info.requested_mode == FuzzMode.AI:
            mode_label = f"ai -> {mode_label}"
        print(f"Type: {YELLOW}{packet_name}{RESET} | Mode: {GREEN}{mode_label}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        
        if info.mutations:
            print(f"{BOLD}Mutations:{RESET}")
            for m in info.mutations:
                orig_str = self._format_value(m.original)
                fuzz_str = self._format_value(m.fuzzed)
                print(f"  {GREEN}→{RESET} {m.field}: {DIM}{orig_str}{RESET} → {YELLOW}{fuzz_str}{RESET} ({m.strategy})")
        
        if info.byteflips:
            print(f"{BOLD}Byteflip:{RESET} {len(info.byteflips)} mutations")
            for flip in info.byteflips[:5]:
                print(f"  {GREEN}→{RESET} offset {flip.offset}: {DIM}0x{flip.original:02x}{RESET} → {YELLOW}0x{flip.fuzzed:02x}{RESET}")
            if len(info.byteflips) > 5:
                print(f"  {DIM}→ ... and {len(info.byteflips) - 5} more{RESET}")
        
        if not info.mutations and not info.byteflips:
            print(f"{DIM}Mutations: none (clean packet){RESET}")
        
        print(f"{CYAN}{'='*70}{RESET}")
        
        size_change = info.fuzzed_size - info.original_size
        size_str = f"{info.fuzzed_size} bytes"
        if size_change != 0:
            sign = '+' if size_change > 0 else ''
            size_str += f" ({sign}{size_change} from original {info.original_size})"
        print(f"Size: {size_str}")
        
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
        elif isinstance(value, list):
            return f"[{len(value)} items]"
        elif isinstance(value, str):
            if len(value) > 20:
                return f'"{value[:20]}..."'
            return f'"{value}"'
        else:
            return str(value)


# =============================================================================
# Limited v1 Migration API
# =============================================================================

class ProtocolFuzzer:
    """
    Limited migration shim for manual v1-style packet builders.
    
    This intentionally preserves only set_mode(), fuzz(), and fuzz_buffer(); it
    is not a drop-in implementation of the v1 ProtocolFuzzer API.
    
        class MyFuzzer(ProtocolFuzzer):
            def build_packet(self):
                buf = struct.pack('<H', self.fuzz(FieldType.LENGTH, 64))
                # ... manual building
    
    New code should use the Framework class with declarative Packet definitions.
    """
    
    def __init__(self):
        self._framework = Framework(verbose=False)
        self._fuzz_mode = FuzzMode.FIELD
    
    def fuzz(self, field_type: FieldType, nominal: int = 0, **kwargs) -> int:
        """
        Legacy single-field fuzzing.
        
        Args:
            field_type: Type of field being fuzzed
            nominal: Nominal (expected) value
            **kwargs: Additional options (ignored for compatibility)
        
        Returns:
            Fuzzed value
        """
        if self._fuzz_mode == FuzzMode.CLEAN:
            return nominal
        
        fuzzed, _ = get_fuzz_integer(field_type, nominal)
        return fuzzed
    
    def fuzz_buffer(self, size: int) -> bytes:
        """
        Legacy buffer generation.
        
        Args:
            size: Nominal buffer size
        
        Returns:
            Fuzzed buffer
        """
        if self._fuzz_mode == FuzzMode.CLEAN:
            return b'\x00' * size
        
        fuzzed, _ = get_fuzz_buffer(size)
        return fuzzed
    
    def set_mode(self, mode: Union[str, FuzzMode]):
        """Set the fuzzing mode."""
        if isinstance(mode, str):
            mode = FuzzMode(mode)
        elif not isinstance(mode, FuzzMode):
            raise TypeError("mode must be a FuzzMode or valid mode string")
        self._fuzz_mode = mode


# =============================================================================
# Convenience Functions
# =============================================================================

def get_fuzz_value(field_type: FieldType, nominal: int = 0) -> int:
    """
    Get a single fuzzed value.
    
    Convenience function for simple use cases.
    
    Args:
        field_type: Type of field
        nominal: Nominal value
    
    Returns:
        Fuzzed value
    """
    value, _ = get_fuzz_integer(field_type, nominal)
    return value


def get_fuzz_size(size_type: FieldType = FieldType.DWORD) -> int:
    """
    Get a fuzzed size value.
    
    Convenience function for LENGTH/COUNT fields.
    """
    return get_fuzz_value(size_type, 0)


def fuzz_buffer(size: int) -> bytes:
    """
    Get a fuzzed buffer.
    
    Convenience function for BYTES fields.
    """
    buf, _ = get_fuzz_buffer(size)
    return buf

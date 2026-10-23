# OffByWon 2.0 Framework

OffByWon 2.0 is a Python framework for describing, serializing, and mutating
network protocol packets. Packet layouts are defined as ordered `Field`
objects in a `Packet` subclass. The framework serializes those fields, resolves
declared length/count/offset relationships, and applies type-aware or raw-byte
mutations.

The core package produces packet bytes and mutation metadata. It does not open
network connections, schedule a campaign, monitor a target process, or decide
whether a missing response is a crash. Calling code is responsible for
transport, protocol state, liveness checks, and target-side monitoring.

This document covers the `offbywon` framework package. Protocol-specific
clients, example fuzzers, and target services are separate integrations.

Use OffByWon only against systems for which you have authorization to test.

## Contents

- [OffByWon 1.0 and 2.0](#offbywon-10-and-20)
- [Requirements and installation](#requirements-and-installation)
- [Build your first fuzzer in five minutes](#build-your-first-fuzzer-in-five-minutes)
- [Minimal example](#minimal-example)
- [Packet model](#packet-model)
- [Field reference](#field-reference)
- [Relationships and nested values](#relationships-and-nested-values)
- [Structured mutation values](#structured-mutation-values)
- [Fuzzing modes](#fuzzing-modes)
- [AI-specific usage](#ai-specific-usage)
- [Field selection and mutation counts](#field-selection-and-mutation-counts)
- [Reproducibility and mutation metadata](#reproducibility-and-mutation-metadata)
- [Framework API](#framework-api)
- [DER/ASN.1 and NDR](#derasn1-and-ndr)
- [Migration from OffByWon v1](#migration-from-offbywon-v1)
- [Tests](#tests)
- [Framework source layout](#framework-source-layout)

## OffByWon 1.0 and 2.0

OffByWon 2.0 is a redesign rather than an incremental extension of the v1
API. The main difference is ownership of packet construction and campaign
control:

- v1 is a single-file, imperative toolkit. It combines value generators,
  manual packet builders, raw mutation, output formatting, command-line
  parsing, and protocol-fuzzer session hooks.
- v2 is a package centered on declarative packet definitions. It serializes a
  `Packet`, resolves declared relationships, applies mutations, and returns the
  resulting bytes with structured metadata. The caller owns transport,
  protocol state, scheduling, and target monitoring.

| Area | OffByWon 1.0 | OffByWon 2.0 |
| --- | --- | --- |
| Distribution | One `offbywon.py` module | Installable `offbywon/` package |
| Packet definition | `PacketBuilder` calls or manual `struct.pack()` code | Ordered `Field` objects in a `Packet` subclass |
| Field model | Seven semantic categories: string, integer, length, offset, bytes, ASN.1/DER, and array | 47 explicit wire types covering integer encodings, relationships, data, compound structures, DER, and NDR |
| Relationships | The protocol implementation calculates and inserts lengths, counts, and offsets | `LENGTH`, `COUNT`, and `OFFSET` fields resolve their declared targets during serialization |
| Structured mutation | `Fuzzer` returns mutated byte values and descriptions | Type-aware mutation occurs while the declared packet is serialized |
| Raw mutation | Separate `Mutator` operations | `byteflip`, `blind`, `combined`, and `full` build modes |
| Reproduction | No per-case replay seed in the result | Every build returns its case seed in `FuzzInfo` |
| Result data | Bytes plus strings or operation-specific dictionaries | `FuzzInfo`, `Mutation`, and `ByteFlip` records |
| Campaign support | `ProtocolFuzzer` includes argument parsing, mode selection, logging, and session hooks | Deliberately outside the core package |
| DER/NDR | DER scanning and byte-oriented DER mutation | Declarative DER fields and encoders, plus NDR array serialization |

For the versioned repository layout, preserve the v1 API under the `v1.0.0`
tag and `legacy` branch before updating `main` to v2. The v2 `ProtocolFuzzer`
name is only a small migration shim; it is not the v1 campaign base class. See
[Migration from OffByWon v1](#migration-from-offbywon-v1) for the retained
methods.

## Requirements and installation

The core package supports Python 3.8 and later and has no third-party runtime
dependency.

```console
git clone https://github.com/secorizon/OffByWon.git
cd OffByWon
python3 -m pip install -e .
```

Install the development dependencies when working on the framework:

```console
python3 -m pip install -e '.[dev]'
```

The `offbywon/` directory can also be copied into another Python project when
editable installation is not suitable.

## Build your first fuzzer in five minutes

This example implements a small binary request/response protocol over TCP. It
uses fixed-width little-endian integers, a derived payload length, and a binary
payload. The complete programs are:

- [examples/binary_quickstart_fuzzer.py](examples/binary_quickstart_fuzzer.py)
- [examples/binary_quickstart_server.py](examples/binary_quickstart_server.py)

Use the reference server only as an authorized local target.

### 1. Understand the wire format

The 16-byte request header is followed by `payload_length` bytes:

| Offset | Size | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic `OBW2` | Fixed bytes |
| 4 | 1 | Version | Unsigned byte |
| 5 | 1 | Opcode | Unsigned byte |
| 6 | 2 | Flags | Little-endian word |
| 8 | 4 | Request ID | Little-endian double word |
| 12 | 4 | Payload length | Little-endian double word |
| 16 | N | Payload | Raw bytes |

The binary response contains the `OBR2` magic, a one-byte status, the echoed
request ID, a four-byte payload length, and the response payload. Opcode `1`
echoes the payload and opcode `2` reverses it.

### 2. Declare the request

Constants are excluded from structured selection. `payload_length` names its
target, so the serializer calculates it after serializing `payload`.

```python
from offbywon import Field, FieldType, Packet


class BinaryRequest(Packet):
    fields = [
        Field('magic', FieldType.BYTES, b'OBW2', size=4, fuzz=False),
        Field('version', FieldType.BYTE, 1, fuzz=False),
        Field('opcode', FieldType.BYTE, 1),
        Field('flags', FieldType.WORD, 0),
        Field('request_id', FieldType.DWORD, 0x11223344),
        Field('payload_length', FieldType.LENGTH,
              target='payload', size_type=FieldType.DWORD),
        Field('payload', FieldType.BYTES, b'\x10\x20\x30\x40'),
    ]
```

The clean request is:

```text
4f425732 01 01 0000 44332211 04000000 10203040
```

### 3. Start the reference target

In the first terminal, run:

```console
python3 -m examples.binary_quickstart_server \
  --host 127.0.0.1 \
  --port 9000
```

### 4. Add one transport exchange

The framework returns bytes; the protocol implementation owns the socket and
response decoder. The complete example uses `struct.Struct('<4sBII')` to parse
the binary response header. The essential exchange is:

```python
import socket
import struct


RESPONSE_HEADER = struct.Struct('<4sBII')


def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('incomplete response')
        data += chunk
    return data


def exchange(host, port, packet, timeout=1.0):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(packet)
        sock.shutdown(socket.SHUT_WR)
        header = recv_exact(sock, RESPONSE_HEADER.size)
        magic, status, request_id, payload_length = RESPONSE_HEADER.unpack(header)
        if magic != b'OBR2':
            raise ValueError('invalid response magic')
        payload = recv_exact(sock, payload_length)
        return status, request_id, payload
```

Opening a new connection for every case isolates connection-level parser state
between cases.

### 5. Require a clean baseline

Build and send an unmodified request before fuzzing. If this exchange fails,
fix the packet definition or transport first.

```python
from offbywon import Framework


framework = Framework(verbose=False)
values = {
    'opcode': 1,
    'flags': 0,
    'request_id': 0x11223344,
    'payload': b'\x10\x20\x30\x40',
}

clean = framework.build_clean(BinaryRequest, values)
response = exchange('127.0.0.1', 9000, clean)
expected = (0, values['request_id'], values['payload'])
if response != expected:
    raise RuntimeError('clean binary exchange failed')
```

### 6. Generate, send, and record cases

This loop mutates exactly one 32-bit request ID per case. The generated values
can come from boundary, near-nominal, bit-pattern, magic-value, byte-swap, or
full-range random payload families.

```python
for case_number in range(25):
    packet, info = framework.build(
        BinaryRequest,
        mode='field',
        values=values,
        fields=['request_id'],
        fuzz_count=1,
    )

    try:
        result = exchange('127.0.0.1', 9000, packet)
    except OSError as exc:
        result = str(exc)

    print(case_number, info.seed, packet.hex(), result)
```

Run the complete example from the repository root:

```console
python3 -m examples.binary_quickstart_fuzzer \
  --host 127.0.0.1 \
  --port 9000 \
  --iterations 25 \
  --mode field \
  --field request_id
```

To exercise the declared payload-length relationship instead, run:

```console
python3 -m examples.binary_quickstart_fuzzer --mode length --iterations 25
```

To let OffByWon balance the applicable mutation strategies automatically, run:

```console
python3 -m examples.binary_quickstart_fuzzer --ai --iterations 25
```

AI mode mutates one structured field by default. Use `--fuzz-count N` to raise
that per-packet structured-field limit.

The program first requires a valid binary response to the clean request. It
then prints the seed, packet size, mutation strategy, decoded status, echoed
request ID, and response payload for every case. A timeout or closed connection
is an observation, not proof of a crash. Confirm failures with an independent
liveness check or target-side process monitor.

Add `--seed N` to reproduce the same campaign sequence. To reproduce one
reported case directly, pass its `info.seed` value to `Framework.build(seed=N)`
with the same packet class, mode, and runtime values.

To adapt the example to another protocol:

1. Replace `BinaryRequest.fields` with the protocol's wire layout.
2. Mark constants and framing fields with `fuzz=False`.
3. Express derived values with `LENGTH`, `COUNT`, or `OFFSET` where applicable.
4. Replace `exchange()` with the required TCP, UDP, or session-aware transport.
5. Define what constitutes a valid clean response and require it before the
   campaign starts.
6. Store `info.seed` and the final packet bytes when a liveness or target-side
   monitor reports a failure.

## Minimal example

```python
from offbywon import Field, FieldType, Framework, Packet


class Message(Packet):
    fields = [
        Field('version', FieldType.BYTE, 1, fuzz=False),
        Field(
            'payload_length',
            FieldType.LENGTH,
            target='payload',
            size_type=FieldType.WORD,
        ),
        Field('payload', FieldType.BYTES, b''),
    ]


framework = Framework(verbose=False)

clean = framework.build_clean(Message, {'payload': b'hello'})
assert clean == b'\x01\x05\x00hello'

fuzzed, info = framework.build(
    Message,
    mode='field',
    values={'payload': b'hello'},
    fields=['payload'],
)

print(fuzzed.hex())
print(info.seed)
for mutation in info.mutations:
    print(mutation.field, mutation.strategy, mutation.original, mutation.fuzzed)

# Rebuild the same case, including field selection and mutation values.
replayed, replay_info = framework.build(
    Message,
    mode='field',
    values={'payload': b'hello'},
    fields=['payload'],
    seed=info.seed,
)
assert replayed == fuzzed
```

`build_clean()` returns bytes. `build()` returns `(bytes, FuzzInfo)`.

## Packet model

A packet is an ordered list of `Field` and `Marker` objects:

```python
class Header(Packet):
    fields = [
        Field('message_type', FieldType.WORD_BE, 1),
        Field('flags', FieldType.DWORD, 0),
        Field('body_length', FieldType.LENGTH,
              target='body', size_type=FieldType.DWORD_BE),
        Field('body', FieldType.BYTES, b''),
    ]
```

Class-level field definitions are cloned for every packet instance. Runtime
values may be supplied to the packet constructor or through `Framework.build()`.
Unknown field names, duplicate declarations, invalid option combinations, and
unresolved references raise an exception.

`fuzz=False` excludes a field from structured selection. It does not protect
the resulting bytes from packet-level byteflip or blind modes.

## Field reference

OffByWon 2.0 defines 47 field types.

### Fixed-width integers

| Type | Width | Encoding |
| --- | ---: | --- |
| `BYTE`, `SBYTE` | 8 bits | unsigned/signed byte |
| `WORD`, `SWORD` | 16 bits | little-endian |
| `DWORD`, `SDWORD` | 32 bits | little-endian |
| `QWORD`, `SQWORD` | 64 bits | little-endian |
| `WORD_BE` | 16 bits | big-endian unsigned |
| `DWORD_BE` | 32 bits | big-endian unsigned |
| `QWORD_BE` | 64 bits | big-endian unsigned |

### Variable-width integers

| Type | Encoding |
| --- | --- |
| `VARINT` | QUIC variable-length integer, range `0` through `2^62 - 1` |
| `VARINT_SIGNED` | signed value encoded with ZigZag followed by ULEB128 |
| `ULEB128` | unsigned LEB128 |
| `SLEB128` | signed LEB128 |

### Data fields

| Type | Behavior and options |
| --- | --- |
| `BYTES` | Raw bytes; optional `size` or `size_from` |
| `STRING` | Text; `encoding` defaults to `utf-16-le`; optional `null_terminated`, `size`, or `size_from` |
| `GUID` | 16-byte Microsoft GUID wire layout; accepts a UUID string or bytes |
| `RESERVED` | Zero-filled in clean mode; `size` defaults to four bytes |

In clean mode, fixed-size byte and string values are truncated or zero-padded
to their declared size. A selected fuzz mutation may intentionally violate that
size.

### Relationship and layout fields

| Type | Main options |
| --- | --- |
| `LENGTH` | `target`, `size_type`, optional `includes_self` |
| `COUNT` | `target`, `size_type` |
| `OFFSET` | `target`, `size_type`, optional `base`, `relative`, and `skip` |
| `PADDING` | `align`; optional `relative_to` marker |
| `Marker` | Named zero-width position used as an offset or padding base |

`size_type` for `LENGTH`, `COUNT`, and `OFFSET` must be a fixed-width integer
type. It defaults to `DWORD`.

### Compound fields

| Type | Behavior and options |
| --- | --- |
| `ARRAY` | Repeated values; `element` may be a `FieldType` or `Packet` class; optional `element_size` and `count_from` |
| `STRUCT` | Nested `Packet`; requires `element=PacketSubclass` |
| `UNION` | Selects a field or packet from `choices` using an earlier `selector`; optional fallback `element` |

An array can contain fixed-size scalar values, other field types, raw byte
elements, or nested packet instances. A discriminated union can select a
`FieldType`, `Field`, or `Packet` subclass.

### DER and NDR fields

DER fields are:

```text
DER_SEQUENCE          DER_SET               DER_INTEGER
DER_OCTET_STRING      DER_BIT_STRING        DER_OID
DER_UTF8_STRING       DER_PRINTABLE_STRING  DER_IA5_STRING
DER_UTC_TIME          DER_GENERALIZED_TIME  DER_BOOLEAN
DER_NULL              DER_ENUMERATED        DER_CONTEXT
DER_APPLICATION       DER_PRIVATE           DER_ANY
```

NDR array fields are `NDR_CONFORMANT`, `NDR_VARYING`, and
`NDR_CONFORMANT_VARYING`.

## Relationships and nested values

`LENGTH`, `COUNT`, and `OFFSET` are written as placeholders and resolved after
the containing packet has been serialized. Their targets may therefore appear
later in the packet. References used by `size_from`, `count_from`, and a union
`selector` must refer to an earlier serialized field.

```python
from offbywon import Field, FieldType, Marker, Packet


class RecordList(Packet):
    fields = [
        Marker('packet_start'),
        Field('record_count', FieldType.COUNT,
              target='records', size_type=FieldType.WORD),
        Field('records_offset', FieldType.OFFSET,
              target='records', base='packet_start',
              size_type=FieldType.WORD),
        Field('records', FieldType.ARRAY,
              element=FieldType.DWORD, element_size=4),
    ]
```

Runtime values support dotted paths for nested structures:

```python
values = {
    'header.version': 3,
    'header.session_id': 0x11223344,
    'body': b'data',
}
```

Field targeting also accepts dotted paths. Array elements can be addressed by
their actual index or with `[]`, for example `records[].value`.

## Structured mutation values

Structured modes mutate the logical value before or during serialization. A
fixed-width integer remains representable by its declared field type. Native
integer fields use the payload families below; `LENGTH`, `COUNT`, and `OFFSET`
use relation-specific mismatches after their actual values have been resolved.

Integer payload families include:

- Type-specific boundary values around powers of two and signed transitions.
- Small integers (`0..255` for unsigned types and the applicable signed range).
- Values near the original using positive and negative deltas.
- One-hot and one-cold bit patterns.
- The original value with one bit changed.
- Bitwise inversion and byte swapping of the original value.
- Repeated-byte and alternating-bit patterns.
- Debug and magic values such as `0xDEADBEEF`, `0xBAADF00D`, and
  `0xCCCCCCCC`, fitted to the field width.
- ASCII-derived integer patterns.
- Partial-width and sign-extension cases.
- Uniform random values across the complete representable range.

The framework selects a payload family and one value for each selected integer
field. It does not exhaustively enumerate every value in a field's numeric
domain.

`BYTES` mutations use one of these strategies:

- overflow with an `A`-filled buffer selected from configured sizes up to
  10,000,000 bytes, or twice the nominal size when it is already beyond that
  configured range;
- zero fill;
- repeated special pattern;
- random bytes of the nominal size;
- truncation;
- empty value.

The current special byte patterns include null and `0xff` bytes, `A`, a format
string, a basic SQL string, a Windows path traversal string, a UTF-8 BOM, and
UTF-16-style null bytes.

`STRING` mutations include overflow text, an empty string, Unicode edge values,
and embedded nulls. `GUID` mutations include zero, all-ones, random, and
boundary layouts. Arrays can insert, remove, duplicate, expand, or mutate an
element. DER and NDR use format-specific mutations described below.

## Fuzzing modes

| Mode | Operation |
| --- | --- |
| `clean` | Serialize without mutation. |
| `ai` | Select one applicable concrete strategy for each build using coverage-balanced scheduling. Structured strategies mutate one field by default. |
| `field` | Mutate selected logical fields according to their type. `STRUCT` and `PADDING` are not directly selected; nested fields may be selected. |
| `length` | Automatically select only `LENGTH`, `COUNT`, and `OFFSET` relation fields and emit mismatches. A native integer relation can be selected explicitly. |
| `array` | Select `ARRAY` and `COUNT` fields. Arrays insert, remove, or duplicate elements; `array_expand=True` permits boundary-sized expansion up to `array_max`. |
| `byteflip` | Serialize first, then change bytes at randomly selected positions. Packet length is preserved. |
| `blind` | Serialize first, then apply one packet-level transformation: truncate, extend with random bytes, corrupt a region, or shuffle a region. |
| `combined` | Apply structured field mutation and then byteflips. |
| `full` | Apply structured mutation, byteflips, and one blind packet-level transformation. Array behavior is available when an array is selected. |

Blind mode is randomized but does not replace the entire packet with random
data. It retains some or all of the serialized packet and applies one of the
listed transformations. Protocols with integrity, encryption, or framing gates
may reject a blind mutation before it reaches deeper parsers. Calling code can
use structured mutation and then recompute those protocol protections.

Blind mode applies one packet-level transformation per build. It does not use
`fields`, `fuzz_count`, or `byteflip_count`; those controls apply to the mode
components described above.

## AI-specific usage

This section is written for AI agents that generate, launch, or supervise an
OffByWon campaign. Unless a human has requested a particular mutation strategy,
an AI should enable automatic mode with `--ai`. In framework code, the
equivalent setting is `mode='ai'`.

The core package is transport-independent and does not impose one campaign
command line. A protocol fuzzer built with OffByWon should expose `--ai` and
map it directly to the framework mode:

```python
parser.add_argument(
    '--ai',
    action='store_true',
    help='Balance applicable fuzzing strategies automatically',
)
args = parser.parse_args()

mode = 'ai' if args.ai else 'field'
packet, info = framework.build(
    Message,
    mode=mode,
    values=runtime_values,
)
```

The included binary quickstart implements that convention:

```console
python3 -m examples.binary_quickstart_fuzzer --ai --iterations 100
```

An AI using the framework API directly should request the same policy on every
fuzzing round:

```python
framework = Framework(verbose=False, seed=campaign_seed)

for case_number in range(iterations):
    packet, info = framework.build(
        Message,
        mode='ai',
        values=runtime_values,
    )
    result = exchange(packet)
```

### Why an AI should use `--ai`

An autonomous client often lacks enough protocol-specific evidence to choose
one mutation family in advance. Automatic mode provides the broadest balanced
strategy coverage available from OffByWon without external target
instrumentation:

- The framework considers `field`, `length`, `array`, `byteflip`, `blind`,
  `combined`, and `full`.
- It excludes structured strategies that cannot mutate the declared packet or
  the explicitly requested fields.
- It chooses among the least-used eligible strategies on every build. Ties are
  randomized, so every eligible strategy is exercised before one is repeatedly
  favored.
- It selects one structured field by default. This keeps individual cases
  attributable and reproducible while the campaign rotates through different
  mutation families.
- Each result records the requested mode, concrete selected mode, mutations,
  byteflips, packet sizes, and case seed.

Selecting one fixed mode for the whole campaign concentrates testing on one
mutation surface. For example, a blind-only campaign may never exercise valid
deeply parsed messages, while a field-only campaign does not test raw packet
handling. Automatic mode covers both classes and the available composite and
relationship strategies.

This is strategy coverage, not feedback-guided code coverage. OffByWon does not
receive branch, edge, sanitizer, or process-state feedback from the target. An
AI must not claim that `--ai` maximized executed target code unless a separate
instrumentation system provides that evidence.

### Recommended AI workflow

1. Confirm that the target is authorized and identify its transport, protocol
   state, authentication requirements, and valid runtime field values.
2. Build and exchange a clean packet with `Framework.build_clean()`. Do not
   begin fuzzing until the target accepts the baseline.
3. Start an independent process, journal, sanitizer, debugger, or service-health
   monitor on the target. A timeout or missing response alone is not proof of a
   crash.
4. Launch the protocol fuzzer with `--ai`, or call
   `Framework.build(mode='ai')` for every fuzzing round.
5. Start with the default one-field budget. Increase `fuzz_count` only when the
   campaign requires multi-field interactions.
6. Record the final packet bytes, concrete strategy, case seed, response, and
   target-side evidence for every suspected failure.
7. Reproduce a candidate with its concrete mode and seed before changing the
   campaign configuration.

A minimal baseline-first loop is:

```python
framework = Framework(verbose=False, seed=campaign_seed)

clean = framework.build_clean(Message, runtime_values)
baseline = exchange(clean)
if not valid_baseline(baseline):
    raise RuntimeError('clean baseline failed')

for case_number in range(iterations):
    packet, info = framework.build(
        Message,
        mode='ai',
        values=runtime_values,
    )
    response = exchange(packet)
    record_case(case_number, packet, info, response)
```

Target monitoring and crash confirmation remain responsibilities of the
campaign runner. The framework produces packets and mutation metadata; it does
not prove that a target process crashed.

### Mutation budgets in AI mode

AI mode defaults to at most one structured field and one byteflip when the
selected concrete strategy contains those components:

```python
packet, info = framework.build(
    Message,
    mode='ai',
    fuzz_count=1,
    byteflip_count=1,
)
```

`fuzz_count` limits structured field mutations only. Composite strategies can
still perform additional operations:

- `combined` applies structured mutation followed by byteflips;
- `full` applies structured mutation, byteflips, and one blind transformation;
- `blind` performs one packet-level transformation and ignores
  `fuzz_count`;
- `byteflip` performs no structured field mutation.

A protocol fuzzer that exposes the framework controls should keep the budgets
independent:

```console
python3 your_protocol_fuzzer.py \
  --ai \
  --fuzz-count 3 \
  --byteflip-count 1
```

This requests up to three structured fields when a structured strategy is
selected and one byteflip when a byteflip component is selected. `--ai` should
be mutually exclusive with CLI switches that force a particular strategy,
because automatic mode makes that selection for every packet.

### Recording and replaying AI-generated cases

In AI mode, `FuzzInfo.requested_mode` is `FuzzMode.AI` and `FuzzInfo.mode`
is the concrete strategy used for that packet:

```python
record = {
    'requested_mode': info.requested_mode.value,
    'concrete_mode': info.mode.value,
    'seed': info.seed,
    'packet_hex': packet.hex(),
}
```

Replay one case with the recorded concrete mode, not with a fresh automatic
selection:

```python
replayed, replay_info = framework.build(
    Message,
    mode=info.mode,
    values=runtime_values,
    seed=info.seed,
)
assert replayed == packet
```

A complete automatic campaign is reproducible when a fresh `Framework` uses
the same constructor seed and receives the same sequence of build calls. Store
the final bytes as well as the seed because later packet-definition or
framework changes can alter seed-based generation.

## Field selection and mutation counts

The selection controls apply to structured modes (`field`, `length`, `array`,
`combined`, and `full`) and to the structured component selected by `ai`:

```python
data, info = framework.build(
    Message,
    mode='field',
    fields=['header.flags', 'payload'],
    fuzz_count=1,
)
```

- With neither `fields` nor `fuzz_count`, `Framework` selects between one and
  five eligible fields, limited by the number available. AI mode is the
  exception: it selects one eligible field by default.
- `fields` restricts selection to the named fields. Unknown or ineligible names
  raise `ValueError`.
- `fuzz_count` is the maximum number of structured fields selected in one
  packet. It is not the number of candidate values generated and it does not
  include post-serialization byteflips.
- With both `fields` and `fuzz_count`, fields are mutated in serialization order
  until the limit is reached.
- `fuzz_count=0` disables structured field mutations.

Byteflip count is controlled separately:

```python
data, info = framework.build(
    Message,
    mode='combined',
    fuzz_count=1,
    byteflip_count=1,
)
```

This produces at most one structured field mutation and one byteflip. If
`byteflip_count` is omitted, byteflip and combined modes choose between one and
five positions, limited by the packet length. `byteflip_count=0` disables the
byteflip component.

## Reproducibility and mutation metadata

Each call to `Framework.build()` uses a case seed and returns it in
`FuzzInfo.seed`. Passing that seed to another build with the same packet class,
concrete mode, and values reproduces field selection and generated mutation
values.

`Framework(seed=...)` produces a reproducible sequence of case seeds. The
per-build `seed=` argument reproduces one exact case.

For AI mode, `FuzzInfo.mode` is the concrete strategy selected for the case and
`FuzzInfo.requested_mode` is `FuzzMode.AI`. Reproduce one AI-generated case by
passing `mode=info.mode` and `seed=info.seed`. Replaying with `mode='ai'`
instead also depends on the scheduler's preceding strategy counts. Two fresh
frameworks constructed with the same seed and called in the same order produce
the same complete AI campaign sequence.

```python
from typing import List, Optional


@dataclass
class FuzzInfo:
    mode: FuzzMode
    mutations: List[Mutation]
    byteflips: List[ByteFlip]
    array_expansions: List[str]
    length_mismatches: List[str]
    original_size: int
    fuzzed_size: int
    seed: Optional[int]
    requested_mode: Optional[FuzzMode]
```

A `Mutation` records the field path, original value, generated value, strategy,
byte offset, and serialized size. A `ByteFlip` records the offset and original
and replacement bytes. Packet-level blind transformations use the synthetic
field name `<packet>`.

Store both the seed and the final packet bytes when recording a test case. The
bytes remain sufficient for replay if the packet definition or framework code
later changes.

## Framework API

### Construction

```python
Framework(
    verbose: bool = True,
    color: bool = True,
    seed: int = None,
    rng = None,
)
```

Pass either `seed` or a `random.Random`-compatible `rng`, not both.

### Packet building

```python
Framework.build(
    packet_class,
    mode='clean',
    values=None,
    fuzz_count=None,
    fields=None,
    array_expand=False,
    array_max=65535,
    byteflip_count=None,
    seed=None,
) -> Tuple[bytes, FuzzInfo]
```

`array_max` bounds physical array expansion. Set it to a value appropriate for
the target and available memory rather than relying on the default for every
campaign.

```python
Framework.build_clean(packet_class, values=None) -> bytes
```

`build_clean()` is a convenience wrapper for clean serialization and suppresses
framework output for that call.

### Standalone mutation helpers

```python
get_fuzz_integer(field_type, nominal=0, rng=None, strategy=None)
get_fuzz_buffer(size, strategy=None, rng=None)
get_boundaries(field_type)
get_random_boundary(field_type, max_val=None, rng=None)
get_fuzz_value(field_type, nominal=0)
get_fuzz_size(size_type=FieldType.DWORD)
fuzz_buffer(size)
```

`get_fuzz_integer()` and `get_fuzz_buffer()` return `(value, strategy)`.
Supplying an integer strategy name is mainly useful for deterministic manual
packet builders and tests. The final three convenience functions return only
the generated value.

Selectable integer strategy names are `boundary`,
`small_integer`, `zero`, `one`, `max`, `min`, `near_nominal`, `one_hot`,
`one_cold`, `nominal_bit_flip`, `bitwise_not`, `repeated_byte`,
`alternating_bits`, `magic`, `ascii_pattern`, `partial_width`,
`sign_extension`, `byte_swap` where applicable, and `random`. Buffer strategy
selectors are `overflow`, `null`, `pattern`, `random`, `truncate`, and `empty`;
the `null` selector is reported as `null_fill`. A serializer fallback may be
reported as `alternate_boundary` or `alternate_byte` when a randomly selected
value would otherwise leave the input unchanged.

The public value sets are `BYTE_BOUNDARIES`, `WORD_BOUNDARIES`,
`DWORD_BOUNDARIES`, `QWORD_BOUNDARIES`, `VARINT_BOUNDARIES`, `COUNT_VALUES`,
`LENGTH_DELTAS`, `OFFSET_CORRUPTIONS`, and `OVERFLOW_SIZES`.

`ProtocolFuzzer` is a limited v1 migration shim exposing `set_mode()`, `fuzz()`,
and `fuzz_buffer()`. New packet definitions should use `Framework` and `Packet`.

## DER/ASN.1 and NDR

Declarative DER fields support primitive values, sequences, sets, optional
children, and context/application/private tags. Tagged fields accept `tag`,
`implicit`, `children`, `optional`, and `constructed` options as applicable.

DER mutation can change length encodings, integer representations, OIDs, tags,
and child structure. It may intentionally produce encodings that are invalid
under DER, including indefinite or non-minimal lengths, for parser testing.

Common DER encoding and protocol-helper exports include:

```python
from offbywon import (
    DERFuzzer,
    DERTag,
    build_ldap_bind_request,
    build_ldap_message,
    build_ldap_sasl_auth,
    build_spnego_init,
    build_spnego_response,
    encode_der_application,
    encode_der_context,
    encode_der_integer,
    encode_der_octet_string,
    encode_der_sequence,
    wrap_der,
)
```

`encode_der_integer()` returns the content octets of an INTEGER. Wrap it with
`wrap_der(DERTag.INTEGER, ...)` when manually constructing a complete TLV.

The NDR fields serialize the count headers and elements for conformant,
varying, and conformant-varying arrays. They can reference earlier fields for
`max_count`, `offset`, and `actual_count` through `conformant_field`,
`offset_field`, and `actual_field`. Literal defaults use `max_count` and
`ndr_offset`. This is array serialization support, not a complete DCE/RPC NDR
pointer and interface runtime.

## Migration from OffByWon v1

OffByWon 2.0 is a declarative redesign and is not API-compatible with the
single-file v1 implementation.

Use these v2 classes for new code:

- `Framework` for packet construction and mutation;
- `Packet`, `Field`, and `Marker` for layouts;
- `FieldType` for wire encodings;
- `FuzzInfo`, `Mutation`, and `ByteFlip` for case metadata.

The v2 `ProtocolFuzzer` class preserves only:

```text
set_mode()
fuzz()
fuzz_buffer()
```

It does not provide compatibility implementations of the v1 `Fuzzer`,
`PacketBuilder`, `DERScanner`, `ArrayFuzzer`, session helpers, command-line
interface, or v1 field names.

```python
import struct

from offbywon import FieldType, ProtocolFuzzer


class TransitionalBuilder(ProtocolFuzzer):
    def build_packet(self):
        version = self.fuzz(FieldType.BYTE, 1)
        length = self.fuzz(FieldType.WORD, 64)
        body = self.fuzz_buffer(64)
        return struct.pack('<BH', version, length) + body
```

This shim is intended for incremental ports of manual builders. It does not
perform automatic relation fixups; declarative `Packet` definitions do.

## Tests

Install the development dependencies and run the core framework suite:

```console
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

## Framework source layout

```text
offbywon/                         core package
  types.py                       field types, boundary sets, mutation helpers
  packet.py                      Field, Marker, and Packet definitions
  serializer.py                  wire serialization and relation fixups
  framework.py                   build orchestration and mutation metadata
  der.py                         DER encoders, mutations, and protocol helpers
tests/
  test_ai_mode.py                AI strategy scheduling and budgets
  test_framework.py              primary framework behavior
  test_quic_fuzzer.py            QUIC mode and mutation-budget behavior
  test_serialization_matrix.py   field serialization matrix
  test_der_matrix.py             DER serialization and mutation behavior
  test_regressions.py            framework regression tests
examples/
  binary_quickstart_fuzzer.py    minimal baseline-first binary TCP fuzzer
  binary_quickstart_server.py    local reference target for the quickstart
  quic_initial_fuzzer.py         QUIC Initial integration with --ai mode
```

## License and author

OffByWon 2.0 is distributed under the MIT License. See [LICENSE](LICENSE).

Author: Laurent Gaffié  
Website: <https://secorizon.com>  
Source: <https://github.com/secorizon/OffByWon>

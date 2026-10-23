"""Coverage-balanced AI mode behavior."""

import pytest

from offbywon import Field, FieldType, Framework, FuzzMode, Packet


class AICoveragePacket(Packet):
    fields = [
        Field('value', FieldType.DWORD, 0xDEADBEEF),
        Field('payload_length', FieldType.LENGTH, target='payload',
              size_type=FieldType.WORD),
        Field('payload', FieldType.BYTES, b'ABCD'),
        Field('item_count', FieldType.COUNT, target='items',
              size_type=FieldType.BYTE),
        Field('items', FieldType.ARRAY, [1, 2], element=FieldType.BYTE),
    ]


def _structured_mutations(info):
    return [mutation for mutation in info.mutations if mutation.field != '<packet>']


def test_ai_mode_covers_every_applicable_strategy_before_repeating():
    framework = Framework(verbose=False, seed=1234)
    infos = [
        framework.build(AICoveragePacket, mode='ai')[1]
        for _ in range(len(Framework.AI_STRATEGIES))
    ]

    assert {info.mode for info in infos} == set(Framework.AI_STRATEGIES)
    assert all(info.requested_mode == FuzzMode.AI for info in infos)


def test_ai_mode_defaults_to_one_structured_field_and_one_byteflip():
    framework = Framework(verbose=False, seed=4321)

    for _ in range(len(Framework.AI_STRATEGIES)):
        _, info = framework.build(AICoveragePacket, mode='ai')

        if info.mode in {
            FuzzMode.FIELD, FuzzMode.LENGTH, FuzzMode.ARRAY,
            FuzzMode.COMBINED, FuzzMode.FULL,
        }:
            assert len(_structured_mutations(info)) == 1
        if info.mode in {FuzzMode.BYTEFLIP, FuzzMode.COMBINED, FuzzMode.FULL}:
            assert len(info.byteflips) == 1


def test_ai_mode_honors_explicit_fuzz_count():
    framework = Framework(verbose=False, seed=99)

    for _ in range(len(Framework.AI_STRATEGIES)):
        _, info = framework.build(
            AICoveragePacket,
            mode='ai',
            fuzz_count=2,
            byteflip_count=2,
        )
        if info.mode == FuzzMode.FIELD:
            assert len(_structured_mutations(info)) == 2
        if info.mode == FuzzMode.BYTEFLIP:
            assert len(info.byteflips) == 2


def test_ai_mode_skips_inapplicable_length_and_array_strategies():
    class ScalarPacket(Packet):
        fields = [Field('value', FieldType.DWORD, 1)]

    expected = {
        FuzzMode.FIELD,
        FuzzMode.BYTEFLIP,
        FuzzMode.BLIND,
        FuzzMode.COMBINED,
        FuzzMode.FULL,
    }
    framework = Framework(verbose=False, seed=7)
    seen = {
        framework.build(ScalarPacket, mode='ai')[1].mode
        for _ in range(len(expected))
    }

    assert seen == expected


def test_ai_mode_rejects_unknown_explicit_field_before_raw_selection():
    with pytest.raises(ValueError, match='unknown or ineligible'):
        Framework(verbose=False).build(
            AICoveragePacket,
            mode='ai',
            fields=['does_not_exist'],
        )


def test_ai_mode_sequence_is_reproducible_with_framework_seed():
    first = Framework(verbose=False, seed=0xA11)
    second = Framework(verbose=False, seed=0xA11)

    first_cases = [first.build(AICoveragePacket, mode='ai') for _ in range(10)]
    second_cases = [second.build(AICoveragePacket, mode='ai') for _ in range(10)]

    assert first_cases == second_cases


@pytest.mark.parametrize('invalid', [['clean'], ['ai'], []])
def test_ai_selector_rejects_invalid_candidate_sets(invalid):
    with pytest.raises(ValueError):
        Framework(verbose=False).choose_ai_mode(invalid)

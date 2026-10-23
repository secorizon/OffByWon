"""Behavioral coverage for the QUIC example's mutation controls."""

import pytest

pytest.importorskip("cryptography")

from examples.quic_initial_fuzzer import QUICInitialFuzzer


@pytest.mark.parametrize(
    "target",
    ["header", "crypto_frame", "frames", "tls", "transport_params"],
)
def test_combined_mode_has_separate_field_and_byteflip_budgets(target):
    fuzzer = QUICInitialFuzzer()
    fuzzer.fuzz_count = 1
    fuzzer.byteflip_count = 1

    fuzzer.build_packet(fuzz_target=target, mode="combined")

    assert len(fuzzer._current_mutations) == 1
    assert len(fuzzer._current_byteflips) == 1


def test_combined_mode_byteflips_only_the_final_datagram(monkeypatch):
    fuzzer = QUICInitialFuzzer()
    fuzzer.fuzz_count = 1
    fuzzer.byteflip_count = 1
    original = fuzzer.fw._apply_byteflips
    calls = []

    def counted(data, count=None, rng=None):
        calls.append((len(data), count))
        return original(data, count, rng)

    monkeypatch.setattr(fuzzer.fw, "_apply_byteflips", counted)
    fuzzer.build_packet(fuzz_target="crypto_frame", mode="combined")

    assert len(calls) == 1
    assert calls[0][0] >= 1200
    assert calls[0][1] == 1


def test_zero_field_budget_still_allows_requested_byteflip():
    fuzzer = QUICInitialFuzzer()
    fuzzer.fuzz_count = 0
    fuzzer.byteflip_count = 1

    fuzzer.build_packet(fuzz_target="header", mode="combined")

    assert fuzzer._current_mutations == []
    assert len(fuzzer._current_byteflips) == 1


def test_raw_byteflip_mode_does_not_apply_structured_target():
    fuzzer = QUICInitialFuzzer()
    fuzzer.fuzz_count = 1
    fuzzer.byteflip_count = 2

    fuzzer.build_packet(fuzz_target="crypto_frame", mode="byteflip")

    assert fuzzer._current_mutations == []
    assert len(fuzzer._current_byteflips) == 2


def test_blind_mode_records_only_packet_corruption():
    fuzzer = QUICInitialFuzzer()
    fuzzer.fuzz_count = 1

    fuzzer.build_packet(fuzz_target="crypto_frame", mode="blind")

    assert len(fuzzer._current_mutations) == 1
    assert fuzzer._current_mutations[0][0] == "<packet>"
    assert fuzzer._current_mutations[0][3].startswith("blind_")
    assert fuzzer._current_byteflips == []


def test_target_selection_includes_length_but_excludes_raw_modes():
    fuzzer = QUICInitialFuzzer()

    fuzzer.fuzz_mode = "length"
    assert fuzzer.select_target() in fuzzer.get_available_targets()

    fuzzer.fuzz_mode = "blind"
    assert fuzzer.select_target() is None

    fuzzer.fuzz_mode = "byteflip"
    assert fuzzer.select_target() is None


def test_cli_parses_independent_mutation_counts():
    fuzzer = QUICInitialFuzzer()
    fuzzer.parse_arguments([
        "-s", "127.0.0.1",
        "--combined",
        "--fuzz-count", "1",
        "--byteflip-count", "2",
    ])

    assert fuzzer.fuzz_mode == "combined"
    assert fuzzer.fuzz_count == 1
    assert fuzzer.byteflip_count == 2


def test_cli_fuzz_count_is_default_byteflip_cap_for_combined_mode():
    fuzzer = QUICInitialFuzzer()
    fuzzer.parse_arguments([
        "-s", "127.0.0.1",
        "--combined",
        "--fuzz-count", "1",
    ])

    assert fuzzer.fuzz_count == 1
    assert fuzzer.byteflip_count == 1

    fuzzer.build_packet(fuzz_target="tls", mode="combined")

    assert len(fuzzer._current_mutations) == 1
    assert len(fuzzer._current_byteflips) == 1


def test_cli_combined_mode_defaults_to_one_byteflip():
    fuzzer = QUICInitialFuzzer()
    fuzzer.parse_arguments([
        "-s", "127.0.0.1",
        "--combined",
    ])

    assert fuzzer.fuzz_count is None
    assert fuzzer.byteflip_count == 1


@pytest.mark.parametrize("option", ["--fuzz-count", "--byteflip-count"])
def test_cli_rejects_negative_mutation_counts(option):
    with pytest.raises(SystemExit):
        QUICInitialFuzzer().parse_arguments([
            "-s", "127.0.0.1", option, "-1",
        ])

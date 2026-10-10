from __future__ import annotations

import pytest

from privacy_gateway import Gateway
from privacy_gateway.leakage import is_weak_value

# Erfundene Werte


@pytest.mark.parametrize("value", ["12", "12/4", "9.9", "123", "Ich", "bei", " 7 ", "ab"])
def test_short_numbers_and_common_words_are_weak(value: str) -> None:
    assert is_weak_value(value)


@pytest.mark.parametrize("value", ["4711", "12/34", "143/123/45678", "Huber", "Ott", "Schwabing", "DE89370400440532013000"])
def test_identifying_values_are_not_weak(value: str) -> None:
    assert not is_weak_value(value)


def test_a_short_parcel_number_does_not_block_other_numbers(gateway: Gateway) -> None:
    text = "Grundbuch von Schwabing Blatt 4711, Flurstück 12. Siehe Seite 12 und den Bescheid vom 12.03.2024."
    result = gateway.pseudonymize(text)
    assert "Seite 12 " in result.text
    assert "12.03.2024" in result.text or "<DATE" in result.text


def test_a_session_does_not_replace_short_numbers_in_later_messages(gateway: Gateway) -> None:
    session = gateway.session("kurze-zahlen")
    session.pseudonymize("Flurstück 12 der Gemarkung Schwabing")
    assert session.pseudonymize("Die Frist beträgt 12 Monate.") == "Die Frist beträgt 12 Monate."


def test_a_known_value_in_capitals_is_repaired_instead_of_blocking(gateway: Gateway) -> None:
    text = "Sehr geehrte Frau Petersen,\nanbei die Unterlagen.\n\nAKTE PETERSEN – bitte aufbewahren"
    result = gateway.pseudonymize(text)
    assert "Petersen" not in result.text
    assert "PETERSEN" not in result.text
    assert result.text.count("<PERSON_FEMALE_001>") == 2


def test_a_session_repairs_a_known_value_in_capitals(gateway: Gateway) -> None:
    session = gateway.session("reparatur")
    out = session.pseudonymize("Sehr geehrte Frau Petersen,\nAKTE PETERSEN")
    assert "PETERSEN" not in out and "Petersen" not in out
    assert session.restore_text(out).count("Petersen") == 2

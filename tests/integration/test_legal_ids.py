from __future__ import annotations

import pytest

from privacy_gateway import Gateway

# Erfundene Werte im Format deutscher Gerichte, Finanzämter, Register und Grundbuchämter
DETECTED = [
    ("LG München I, Az. 12 O 3456/25, Termin", "12 O 3456/25", "CASE_NUMBER"),
    ("Urteil des FG München vom Mai, 4 K 1234/24.", "4 K 1234/24", "CASE_NUMBER"),
    ("BGH, Beschluss IX ZR 123/24 zur Haftung", "IX ZR 123/24", "CASE_NUMBER"),
    ("BVerfG 1 BvR 2345/23 bestätigt", "1 BvR 2345/23", "CASE_NUMBER"),
    ("StA München I, 102 Js 12345/25", "102 Js 12345/25", "CASE_NUMBER"),
    ("Unser Zeichen: 2025/0042-PL, bitte angeben", "2025/0042-PL", "CASE_NUMBER"),
    ("Aktenzeichen 7781/25.", "7781/25", "CASE_NUMBER"),
    ("Steuernummer 143/123/45678 beim Finanzamt", "143/123/45678", "TAX_NUMBER"),
    ("St.-Nr. 12/345/67890", "12/345/67890", "TAX_NUMBER"),
    ("Steuernummer: 9143012345678", "9143012345678", "TAX_NUMBER"),
    ("StNr. 013 815 08153 (Hessen)", "013 815 08153", "TAX_NUMBER"),
    ("eingetragen im Handelsregister, AG München HRB 123456", "HRB 123456", "COMMERCIAL_REGISTER_ID"),
    ("Amtsgericht Charlottenburg HRB 98765 B", "HRB 98765 B", "COMMERCIAL_REGISTER_ID"),
    ("Huber GmbH & Co. KG, HRA 112233", "HRA 112233", "COMMERCIAL_REGISTER_ID"),
    ("Partnerschaftsregister des Amtsgerichts München PR 1234", "PR 1234", "COMMERCIAL_REGISTER_ID"),
    ("Grundbuch von Schwabing Blatt 4711", "4711", "LAND_REGISTER_ID"),
    ("Grundbuchblatt 12345, lastenfrei", "12345", "LAND_REGISTER_ID"),
    ("Band 12 Blatt 345 des Grundbuchs", "345", "LAND_REGISTER_ID"),
    ("Flurstück 123/4 mit 512 m²", "123/4", "PARCEL_ID"),
    ("Fl.Nr. 1234/5 der Gemarkung", "1234/5", "PARCEL_ID"),
    ("Gemarkung Schwabing, Flst. 77", "Schwabing", "LAND_REGISTER_DISTRICT"),
    ("Grundbuch von Schwabing Blatt 4711", "Schwabing", "LAND_REGISTER_DISTRICT"),
]

NOT_DETECTED = [
    "Siehe Blatt 2 der Anlage.",
    "Die PR 2024 lief gut.",
    "§ 13 Abs. 1 Nr. 2 ErbStG",
    "Art. 3 Abs. 1 GG",
    "BStBl II 2024, 123",
]


@pytest.mark.parametrize(("text", "value", "data_class"), DETECTED)
def test_legal_identifier_is_tokenized(
    gateway: Gateway, text: str, value: str, data_class: str
) -> None:
    result = gateway.pseudonymize(text)
    assert value not in result.text
    stored = gateway.vault.load(result.session_id).values()
    assert any(e.value == value and e.data_class == data_class for e in stored), [
        (e.data_class, e.value) for e in stored
    ]
    assert gateway.restore(result.text, result.session_id).text == text


@pytest.mark.parametrize("text", NOT_DETECTED)
def test_ordinary_legal_text_stays_unchanged(gateway: Gateway, text: str) -> None:
    assert gateway.pseudonymize(text).text == text

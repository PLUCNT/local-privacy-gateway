from __future__ import annotations

import base64
import copy

from privacy_gateway_proxy.media import (
    DOCUMENT_NOTICE,
    IMAGE_NOTICE,
    PDF_HEADER,
    SCAN_NOTICE,
    convert_media,
)

# Erfundene Inhalte
LINES = ["Steuerbescheid 2024", "Herr Karl Huber", "IBAN DE89370400440532013000"]
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nnot-really-a-png").decode()


def make_pdf(lines: list[str]) -> bytes:
    """Minimal one-page PDF with a Helvetica text layer (no lines: an empty page)."""
    stream = "BT /F1 12 Tf 50 780 Td 16 TL " + " ".join(f"({z}) Tj T*" for z in lines) + " ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            "/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf, offsets = b"%PDF-1.4\n", []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n{obj}\nendobj\n".encode("latin-1")
    xref = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    pdf += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return pdf


def pdf_block(data: bytes, **extra: object) -> dict:
    source = {"type": "base64", "media_type": "application/pdf", "data": base64.b64encode(data).decode()}
    return {"type": "document", "source": source, **extra}


def image_block(**extra: object) -> dict:
    return {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": PNG}, **extra}


def tool_result(*blocks: dict) -> dict:
    return {"type": "tool_result", "tool_use_id": "toolu_1", "content": list(blocks)}


def body_with(*blocks: dict) -> dict:
    return {"model": "m", "messages": [{"role": "user", "content": list(blocks)}]}


def test_pdf_with_text_layer_becomes_a_text_block() -> None:
    body = body_with(tool_result({"type": "text", "text": "PDF gelesen"}, pdf_block(make_pdf(LINES))))
    new, converted = convert_media(body)
    block = new["messages"][0]["content"][0]["content"][1]
    assert converted == 1
    assert block["type"] == "text"
    assert block["text"].startswith(PDF_HEADER)
    for line in LINES:
        assert line in block["text"]


def test_pdf_without_text_layer_is_replaced_by_the_scan_notice() -> None:
    new, converted = convert_media(body_with(pdf_block(make_pdf([]))))
    assert converted == 1
    assert new["messages"][0]["content"][0] == {"type": "text", "text": SCAN_NOTICE}


def test_unreadable_pdf_is_replaced_by_the_document_notice() -> None:
    new, _ = convert_media(body_with(pdf_block(b"%PDF-1.4 kaputt")))
    assert new["messages"][0]["content"][0] == {"type": "text", "text": DOCUMENT_NOTICE}


def test_invalid_base64_is_replaced_by_the_document_notice() -> None:
    block = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "%%%"}}
    new, _ = convert_media(body_with(block))
    assert new["messages"][0]["content"][0]["text"] == DOCUMENT_NOTICE


def test_images_in_messages_and_tool_results_are_replaced() -> None:
    new, converted = convert_media(body_with(image_block(), tool_result(image_block())))
    content = new["messages"][0]["content"]
    assert converted == 2
    assert content[0] == {"type": "text", "text": IMAGE_NOTICE}
    assert content[1]["content"][0] == {"type": "text", "text": IMAGE_NOTICE}


def test_documents_the_proxy_cannot_read_are_replaced() -> None:
    url_document = {"type": "document", "source": {"type": "url", "url": "https://example.test/a.pdf"}}
    other_binary = {"type": "document", "source": {"type": "base64", "media_type": "image/tiff", "data": PNG}}
    new, converted = convert_media(body_with(url_document, other_binary))
    assert converted == 2
    assert all(b["text"] == DOCUMENT_NOTICE for b in new["messages"][0]["content"])


def test_text_documents_and_other_blocks_stay_untouched() -> None:
    text_document = {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "x"}}
    thinking = {"type": "thinking", "thinking": "t", "signature": "s"}
    body = body_with(text_document, {"type": "text", "text": "Hallo"}, thinking)
    new, converted = convert_media(body)
    assert converted == 0
    assert new == body


def test_cache_control_and_title_are_kept() -> None:
    marker = {"type": "ephemeral"}
    block = pdf_block(make_pdf(LINES), cache_control=marker, title="bescheid.pdf")
    new, _ = convert_media(body_with(block, image_block(cache_control=marker)))
    pdf_text, image_text = new["messages"][0]["content"]
    assert pdf_text["cache_control"] == marker
    assert image_text["cache_control"] == marker
    assert "bescheid.pdf" in pdf_text["text"]


def test_the_original_body_is_not_modified() -> None:
    body = body_with(image_block(), pdf_block(make_pdf(LINES)))
    before = copy.deepcopy(body)
    convert_media(body)
    assert body == before


def test_string_content_and_missing_messages_are_fine() -> None:
    assert convert_media({"messages": [{"role": "user", "content": "Hallo"}]})[1] == 0
    assert convert_media({"model": "m"})[1] == 0

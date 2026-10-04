"""Replace image and binary document blocks by text before a request is pseudonymized."""

from __future__ import annotations

import base64
import binascii
import copy
import io
from typing import Any

from pypdf import PdfReader

IMAGE_NOTICE = "[privacy-gateway: Bild entfernt – Bilder werden nicht übertragen]"
DOCUMENT_NOTICE = "[privacy-gateway: Dokument entfernt – Inhalt lokal nicht lesbar]"
SCAN_NOTICE = "[privacy-gateway: PDF ohne Textebene (Scan?) entfernt]"
PDF_HEADER = "[privacy-gateway: Text lokal aus PDF extrahiert, Layout und Bilder entfernt]"
EMPTY_PAGE = "[Seite ohne Text – entfernt]"
PDF_MEDIA_TYPE = "application/pdf"


def convert_media(body: dict) -> tuple[dict, int]:
    """Return a copy of the request with media blocks replaced by text, and their count."""
    new_body = copy.deepcopy(body)
    converted = 0
    messages = new_body.get("messages")
    if not isinstance(messages, list):
        return new_body, 0
    for message in messages:
        if isinstance(message, dict):
            converted += _convert_list(message.get("content"))
    return new_body, converted


def _convert_list(content: Any) -> int:
    if not isinstance(content, list):
        return 0
    converted = 0
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_result":
            converted += _convert_list(block.get("content"))
            continue
        text = _replacement(block)
        if text is None:
            continue
        new_block: dict[str, Any] = {"type": "text", "text": text}
        if "cache_control" in block:
            new_block["cache_control"] = block["cache_control"]
        content[index] = new_block
        converted += 1
    return converted


def _replacement(block: dict) -> str | None:
    block_type = block.get("type")
    if block_type == "image":
        return IMAGE_NOTICE
    if block_type != "document":
        return None
    source = block.get("source")
    if isinstance(source, dict) and source.get("type") == "text":
        return None
    if not (
        isinstance(source, dict)
        and source.get("type") == "base64"
        and source.get("media_type") == PDF_MEDIA_TYPE
        and isinstance(source.get("data"), str)
    ):
        return DOCUMENT_NOTICE
    text = _pdf_text(source["data"])
    if text is None:
        return DOCUMENT_NOTICE
    if not text:
        return SCAN_NOTICE
    heading = [PDF_HEADER]
    for key in ("title", "context"):
        if isinstance(block.get(key), str):
            heading.append(block[key])
    return "\n".join(heading) + "\n\n" + text


def _pdf_text(data: str) -> str | None:
    """Text of all pages, '' without any text layer, None when the PDF cannot be read."""
    try:
        raw = base64.b64decode(data, validate=True)
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted and not reader.decrypt(""):
            return None
        pages = [page.extract_text() or "" for page in reader.pages]
    except (binascii.Error, ValueError):
        return None
    except Exception:  # noqa: BLE001 – pypdf wirft bei kaputten Dateien beliebige Typen; fail closed
        return None
    if not any(page.strip() for page in pages):
        return ""
    return "\n\n".join(
        f"--- Seite {number} ---\n{page.strip() or EMPTY_PAGE}"
        for number, page in enumerate(pages, 1)
    )

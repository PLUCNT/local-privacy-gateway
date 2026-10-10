"""Prüfseite: blockierte Anfrage ansehen, einmal oder dauerhaft freigeben."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import DetectionReport
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text
from privacy_gateway_proxy import server
from privacy_gateway_proxy.settings import ProxySettings

from .test_e2e import LETTER, UPSTREAM, request_body

OTHER = "1a2b3c4d-1111-2222-3333-555555555555"


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    def leaking(text: str, report: DetectionReport, config: Config, *, counters: dict[str, int] | None = None) -> PseudonymizedText:
        real = pseudonymize_text(text, report, config, counters=counters)
        # unbekannter Platzhalter: nicht reparierbar, landet auf der Prüfseite
        return PseudonymizedText(text=real.text + " <PERSON_999>", assignments=real.assignments)

    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", leaking)
    with Gateway() as instance:
        yield instance


def build(gateway: Gateway, tmp_path: Path, seen: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "msg_1", "content": [{"type": "text", "text": "ok"}]})

    settings = ProxySettings(upstream_base_url=UPSTREAM, allowlist_path=tmp_path / "freigaben.txt")
    app = server.create_app(settings, gateway, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8787")


def review_path(response: httpx.Response) -> str:
    match = re.search(r"http://127\.0\.0\.1:8787(/pruefung/[A-Za-z0-9_-]+)", response.json()["error"]["message"])
    assert match, response.json()
    return match.group(1)


@pytest.mark.asyncio
async def test_a_blocked_request_points_to_its_review_page(gateway: Gateway, tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    async with build(gateway, tmp_path, seen) as client:
        response = await client.post("/v1/messages", json=request_body(LETTER))
        page = await client.get(review_path(response))
    assert response.status_code == 422 and not seen
    assert page.status_code == 200
    assert "&lt;PERSON_999&gt;" in page.text and "blockiert lassen" in page.text
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "leak_review" and e["counts"] for e in events)


@pytest.mark.asyncio
async def test_released_once_the_retry_goes_through(gateway: Gateway, tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    async with build(gateway, tmp_path, seen) as client:
        path = review_path(await client.post("/v1/messages", json=request_body(LETTER)))
        done = await client.post(path, content="d0=once", headers={"content-type": "application/x-www-form-urlencoded"})
        retry = await client.post("/v1/messages", json=request_body(LETTER))
    assert "erneut" in done.text
    assert retry.status_code == 200 and len(seen) == 1
    assert not (tmp_path / "freigaben.txt").exists()


@pytest.mark.asyncio
async def test_released_always_the_value_passes_in_a_new_conversation(gateway: Gateway, tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    async with build(gateway, tmp_path, seen) as client:
        path = review_path(await client.post("/v1/messages", json=request_body(LETTER)))
        await client.post(path, content="d0=always", headers={"content-type": "application/x-www-form-urlencoded"})
    assert "<PERSON_999>" in (tmp_path / "freigaben.txt").read_text(encoding="utf-8")
    async with build(gateway, tmp_path, seen) as client:   # Neustart: Liste wird neu geladen
        other = await client.post("/v1/messages", json=request_body(LETTER, conversation=OTHER))
    assert other.status_code == 200


@pytest.mark.asyncio
async def test_kept_blocked_the_retry_is_still_refused(gateway: Gateway, tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    async with build(gateway, tmp_path, seen) as client:
        path = review_path(await client.post("/v1/messages", json=request_body(LETTER)))
        await client.post(path, content="d0=blocked", headers={"content-type": "application/x-www-form-urlencoded"})
        retry = await client.post("/v1/messages", json=request_body(LETTER))
    assert retry.status_code == 422 and not seen


@pytest.mark.asyncio
async def test_unknown_review_and_foreign_host_are_refused(gateway: Gateway, tmp_path: Path) -> None:
    async with build(gateway, tmp_path, []) as client:
        missing = await client.get("/pruefung/gibt-es-nicht")
        path = review_path(await client.post("/v1/messages", json=request_body(LETTER)))
        foreign = await client.get(path, headers={"host": "evil.example"})
    assert missing.status_code == 404
    assert foreign.status_code == 403

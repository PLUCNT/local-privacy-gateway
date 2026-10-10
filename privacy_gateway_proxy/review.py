"""Local review page for blocked requests: show each finding, release it once or permanently."""

from __future__ import annotations

import html
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from privacy_gateway.leakage import normalize_allowed
from privacy_gateway.model import LeakageError

CONTEXT_CHARS = 60
MAX_REVIEWS = 50
KIND_LABELS = {
    "original_value": "Wert an anderer Stelle nicht ersetzt",
    "residual_finding": "Wert nicht ersetzt",
    "unknown_token": "Platzhalter unbekannt",
}


@dataclass
class LeakSite:
    """One finding with its surrounding text."""

    kind: str
    data_class: str
    before: str
    value: str
    after: str


@dataclass
class Review:
    """A blocked request waiting for a decision."""

    review_id: str
    session_key: str
    sites: list[LeakSite]
    created: float = field(default_factory=time.time)
    decided: bool = False


def leak_sites(exc: LeakageError) -> list[LeakSite]:
    """The findings of a blocked request, one per distinct value and class."""
    text = getattr(exc, "text", "") or ""
    sites: list[LeakSite] = []
    seen: set[tuple[str, str]] = set()
    for leak in exc.leaks:
        value = text[leak.start : leak.end]
        key = (normalize_allowed(value), leak.data_class)
        if key in seen:
            continue
        seen.add(key)
        sites.append(LeakSite(
            leak.kind, leak.data_class,
            text[max(0, leak.start - CONTEXT_CHARS) : leak.start], value, text[leak.end : leak.end + CONTEXT_CHARS],
        ))
    return sites


class ReviewStore:
    """The most recent reviews, in memory only, addressed by an unguessable id."""

    def __init__(self) -> None:
        self._reviews: OrderedDict[str, Review] = OrderedDict()

    def add(self, session_key: str, sites: list[LeakSite]) -> Review:
        review = Review(secrets.token_urlsafe(12), session_key, sites)
        self._reviews[review.review_id] = review
        while len(self._reviews) > MAX_REVIEWS:
            self._reviews.popitem(last=False)
        return review

    def get(self, review_id: str) -> Review | None:
        return self._reviews.get(review_id)


def load_allowlist(path: Path | None) -> set[str]:
    """Permanently released values, normalized; a missing file means none."""
    if path is None or not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {normalize_allowed(line) for line in lines if line.strip() and not line.startswith("#")}


def append_allowlist(path: Path, values: list[str]) -> None:
    """Add values to the permanent release list (one per line, created on first use)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", encoding="utf-8") as handle:
        if new:
            handle.write("# Dauerhaft freigegebene Werte – gehen im Klartext an Anthropic. Zeile löschen = Freigabe zurücknehmen.\n")
        for value in values:
            handle.write(value.strip().replace("\n", " ") + "\n")


def decisions(sites: list[LeakSite], form: dict[str, list[str]]) -> dict[str, list[LeakSite]]:
    """Group the sites by the choice made on the form (default: blocked)."""
    result: dict[str, list[LeakSite]] = {"once": [], "always": [], "blocked": []}
    for index, site in enumerate(sites):
        choice = (form.get(f"d{index}") or ["blocked"])[0]
        result[choice if choice in result else "blocked"].append(site)
    return result


_STYLE = """
body{font-family:Calibri,Segoe UI,sans-serif;background:#F7F5F3;color:#3D3D3C;margin:0;padding:32px 40px;max-width:1100px}
h1{font-family:Georgia,serif;font-weight:400;font-size:28px;margin:0 0 6px}
p.hinweis{background:#F3E8E6;border-radius:10px;padding:12px 16px;margin:16px 0}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #E6E2DE;vertical-align:top;font-size:15px}
th{background:#ECE8E4}
td.kontext{font-family:Consolas,monospace;font-size:13px;color:#5A5958;max-width:520px;word-break:break-word}
mark{background:#F3E8E6;color:#8E2C29;font-weight:700;padding:0 2px}
label{display:block;white-space:nowrap}
button{margin-top:18px;background:#8E2C29;color:#fff;border:0;border-radius:8px;padding:10px 20px;font-size:15px;cursor:pointer}
"""


def render_page(review: Review) -> str:
    """The review page for one blocked request."""
    rows = []
    for index, site in enumerate(review.sites):
        context = f"…{html.escape(site.before)}<mark>{html.escape(site.value)}</mark>{html.escape(site.after)}…"
        options = "".join(
            f'<label><input type="radio" name="d{index}" value="{value}"{" checked" if value == "blocked" else ""}> {label}</label>'
            for value, label in (("blocked", "blockiert lassen"), ("once", "einmal durchlassen"), ("always", "immer durchlassen"))
        )
        rows.append(
            f"<tr><td>{html.escape(site.data_class or '–')}</td><td>{html.escape(KIND_LABELS.get(site.kind, site.kind))}</td>"
            f'<td class="kontext">{context}</td><td>{options}</td></tr>'
        )
    done = '<p class="hinweis">Für diese Prüfung wurde bereits entschieden.</p>' if review.decided else ""
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Privacy Gateway – Prüfung</title><style>{_STYLE}</style></head>
<body><h1>Blockierte Anfrage prüfen</h1>
<p>Der Privacy Gateway hat {len(review.sites)} Stelle(n) gefunden, die nach dem Ersetzen noch nach Klartext aussehen. Die Anfrage wurde <b>nicht</b> gesendet.</p>
<p class="hinweis"><b>Achtung:</b> Was Sie durchlassen, geht <b>im Klartext</b> an Anthropic. „Einmal“ gilt für diese Unterhaltung, „immer“ schreibt den Wert in die lokale Freigabeliste.</p>
{done}<form method="post"><table><tr><th>Klasse</th><th>Art</th><th>Textstelle</th><th>Entscheidung</th></tr>{"".join(rows)}</table>
<button type="submit">Entscheidung übernehmen</button></form></body></html>"""


def render_done(once: int, always: int, blocked: int) -> str:
    """Confirmation after a decision."""
    next_step = ("Senden Sie Ihre Nachricht in Claude Code jetzt erneut, z. B. mit „weiter“."
                 if blocked == 0 else
                 "Mindestens eine Stelle bleibt blockiert – die Anfrage wird weiter abgelehnt. Starten Sie für diesen Inhalt eine neue Sitzung oder geben Sie die Stelle frei.")
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Privacy Gateway – Entscheidung</title><style>{_STYLE}</style></head>
<body><h1>Entscheidung übernommen</h1><p>Einmal durchgelassen: {once} · Immer durchgelassen: {always} · Blockiert: {blocked}</p>
<p class="hinweis">{next_step}</p></body></html>"""

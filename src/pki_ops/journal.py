"""Journal JSONL horodaté des messages, appels d'outils, refus et erreurs."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any


class Journal:
    def __init__(self, chemin: Path | None = None, identifiant: str = ""):
        self.chemin, self.identifiant, self.evenements = chemin, identifiant, []
        if chemin:
            chemin.parent.mkdir(parents=True, exist_ok=True)

    def ecrire(self, type_: str, agent: str | None = None, **champs: Any) -> None:
        ev = {"t": dt.datetime.now(dt.timezone.utc).isoformat(), "id": self.identifiant, "type": type_,
              "agent": agent, **champs}
        self.evenements.append(ev)
        if self.chemin:
            with self.chemin.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")


def lire_journal(chemin: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in chemin.read_text(encoding="utf-8").splitlines() if x]

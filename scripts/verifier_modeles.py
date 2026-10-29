"""Vérifie que les modèles Ollama installés ont les digests déclarés dans config/experiment.yaml.

Code de sortie 0 si tout est conforme, 1 sinon (le message dit quel modèle manque ou diffère).
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import yaml

RACINE = Path(__file__).resolve().parents[1]


def main(etiquettes: list[str]) -> int:
    cfg = yaml.safe_load((RACINE / "config" / "experiment.yaml").read_text(encoding="utf-8"))
    try:
        installes = {m["name"]: "sha256:" + m["digest"] for m in httpx.get(
            f"{cfg['ollama']['hote']}/api/tags", timeout=5).json()["models"]}
    except (httpx.HTTPError, KeyError, ValueError) as e:
        print(f"Ollama injoignable : {e}")
        return 1
    code = 0
    for m in cfg["modeles"].values():
        if etiquettes and m["etiquette"] not in etiquettes:
            continue
        reel = installes.get(m["etiquette"])
        if reel is None:
            print(f"ABSENT   {m['etiquette']}  (ollama pull {m['etiquette']})"); code = 1
        elif reel != m["digest"]:
            print(f"DIFFERENT {m['etiquette']} : installé {reel[:19]}…, attendu {m['digest'][:19]}…"); code = 1
        else:
            print(f"OK       {m['etiquette']}  {reel[:19]}…")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

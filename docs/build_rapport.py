"""Construit docs/rapport.pdf à partir de docs/rapport.md et de results/metrics.json.

Chaque nombre du rapport s'écrit {{chemin.dans.metrics|format}} : il est lu dans metrics.json au moment de la
construction, et la construction échoue si la clé n'existe pas. Aucun résultat n'est donc saisi à la main.
Formats : n0, n1, n2, n3 (nombre), pct (n1 + « %»), ms (« moyenne ± écart-type » d'un bloc {moyenne, ecart_type}),
raw (tel quel). Variables d'environnement : PKIOPS_RESULTATS (dossier des résultats).
Le PDF est produit par Edge ou Chrome en mode sans interface (impression).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import markdown

RACINE = Path(__file__).resolve().parents[1]
RESULTATS = RACINE / os.environ.get("PKIOPS_RESULTATS", "results")
NAVIGATEURS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
               r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]
MOTIF = re.compile(r"\{\{\s*([a-zA-Z0-9_.\-]+)\s*(?:\|\s*([a-z0-9]+))?\s*\}\}")


def fr(x: float, nd: int) -> str:
    return f"{x:.{nd}f}".replace(".", ",")


def chercher(m: dict, chemin: str):
    cur = m
    for k in chemin.split("."):
        if isinstance(cur, list):
            cur = cur[int(k)]
        elif k in cur:
            cur = cur[k]
        else:
            raise KeyError(f"clé absente de metrics.json : {chemin} (échec sur « {k} »)")
    return cur


def formater(v, fmt: str | None) -> str:
    if fmt in (None, "raw"):
        return str(v)
    if fmt == "ms":
        return f"{fr(v['moyenne'], 1)} ± {fr(v['ecart_type'], 1)}"
    if v is None:
        return "non défini"
    if fmt.startswith("n"):
        return fr(float(v), int(fmt[1:])) if int(fmt[1:]) else str(int(round(float(v))))
    if fmt == "pct":
        return fr(float(v), 1) + "\u202f%"
    raise ValueError(f"format inconnu : {fmt}")


def substituer(texte: str, m: dict) -> str:
    return MOTIF.sub(lambda r: formater(chercher(m, r.group(1)), r.group(2)), texte)


def main() -> None:
    m = json.loads((RESULTATS / "metrics.json").read_text(encoding="utf-8"))
    env_chemin = RESULTATS / "ENVIRONMENT.json"
    if env_chemin.exists():
        m["environnement"] = json.loads(env_chemin.read_text(encoding="utf-8"))
    md = substituer((RACINE / "docs" / "rapport.md").read_text(encoding="utf-8"), m)
    corps = markdown.markdown(md, extensions=["tables", "fenced_code", "footnotes", "toc", "attr_list"])
    css = (RACINE / "docs" / "style.css").read_text(encoding="utf-8")
    page = f"<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>Rapport</title><style>{css}</style></head><body>{corps}</body></html>"
    html = RACINE / "docs" / "rapport.html"
    html.write_text(page, encoding="utf-8", newline="\n")
    nav = next((p for p in NAVIGATEURS if Path(p).exists()), None)
    if nav is None:
        sys.exit("aucun navigateur Chromium trouvé pour produire le PDF")
    pdf = RACINE / "docs" / "rapport.pdf"
    sys.path.insert(0, str(RACINE / "docs"))
    from capturer_terminal import lancer_navigateur
    lancer_navigateur(nav, ["--no-pdf-header-footer", f"--print-to-pdf={pdf}", html.as_uri()], pdf, 180)
    pages = len(re.findall(rb"/Type\s*/Page[^s]", pdf.read_bytes()))
    print(f"{pdf.relative_to(RACINE)} écrit, {pages} pages")


if __name__ == "__main__":
    main()

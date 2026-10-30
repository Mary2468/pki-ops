"""Produit des captures d'écran de terminal à partir de la sortie RÉELLE des commandes (docs/img/*.png).

Chaque commande est exécutée ici ; sa sortie est mise en page comme un terminal puis photographiée par Edge/Chrome
sans interface. Rien n'est écrit à la main : si la commande échoue, la capture montre l'échec.
"""

from __future__ import annotations

import html
import os
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
IMG = RACINE / "docs" / "img"
BIN = RACINE / ".venv" / ("Scripts" if os.name == "nt" else "bin")
NAVIGATEURS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
               r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
               r"C:\Program Files\Google\Chrome\Application\chrome.exe", "/usr/bin/google-chrome", "/usr/bin/chromium"]

# (nom du fichier, commande affichée, argv réel, nb max de lignes affichées)
CAPTURES = [
    ("traiter_legitime", "pkiops traiter leg-00", ["pkiops", "traiter", "leg-00", "--traces", "traces/exemple"], 34),
    ("traiter_injection", "pkiops traiter inj-0", ["pkiops", "traiter", "inj-0"], 30),
    ("rejouer_verifier", "pkiops rejouer traces/exemple/leg-00.jsonl --verifier", ["pkiops", "rejouer", "traces/exemple/leg-00.jsonl", "--verifier"], 34),
    ("mtls", "pkiops experience mtls", ["pkiops", "experience", "mtls"], 40),
    ("ocsp", "pkiops experience ocsp", ["pkiops", "experience", "ocsp"], 40),
    ("compromission", "pkiops experience compromission", ["pkiops", "experience", "compromission"], 30),
    ("name_constraints", "pkiops experience name_constraints", ["pkiops", "experience", "name_constraints"], 30),
    ("registre", "pkiops experience registre", ["pkiops", "experience", "registre"], 30),
    ("tests", "pytest -q --cov", ["python", "-m", "pytest", "-q", "--cov"], 28),
]


def lancer_navigateur(nav: str, args: list[str], fichier: Path, delai: int = 90) -> None:
    """Lance Chrome/Edge sans interface avec un profil jetable ; s'arrête dès que le fichier produit est stable."""
    import shutil
    import tempfile
    import time
    profil = tempfile.mkdtemp(prefix="profil-nav-")
    if fichier.exists():
        fichier.unlink()
    p = subprocess.Popen([nav, "--headless=new", "--disable-gpu", f"--user-data-dir={profil}", "--no-first-run", *args],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fin, taille = time.time() + delai, -1
    while time.time() < fin:
        time.sleep(1.0)
        if fichier.exists() and fichier.stat().st_size > 0:
            if fichier.stat().st_size == taille:
                break
            taille = fichier.stat().st_size
    p.kill()
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    shutil.rmtree(profil, ignore_errors=True)
    if not fichier.exists():
        raise RuntimeError(f"le navigateur n'a pas produit {fichier}")


def executer(argv: list[str]) -> str:
    exe = BIN / (argv[0] + (".exe" if os.name == "nt" else ""))
    cmd = [str(exe)] + argv[1:] if exe.exists() else [sys.executable] + argv[1:] if argv[0] == "python" else argv
    if argv[0] == "python":
        cmd = [str(BIN / ("python.exe" if os.name == "nt" else "python"))] + argv[1:]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    p = subprocess.run(cmd, cwd=RACINE, capture_output=True, text=True, encoding="utf-8", env=env, timeout=600)
    return (p.stdout + p.stderr).rstrip()


def png(nom: str, affiche: str, sortie: str, max_lignes: int, largeur: int = 1000) -> None:
    lignes = []
    for l in sortie.splitlines():
        while len(l) > 118:
            lignes.append(l[:118]); l = "  " + l[118:]
        lignes.append(l)
    if len(lignes) > max_lignes:
        lignes = lignes[:max_lignes - 1] + [f"[… {len(lignes) - max_lignes + 1} lignes non affichées]"]
    corps = f"<span class='p'>$ {html.escape(affiche)}</span>\n" + "\n".join(html.escape(l) for l in lignes)
    page = ("<!doctype html><meta charset='utf-8'><style>body{margin:0;background:#1e1f24}"
            "pre{margin:0;padding:14px 18px;color:#d7dae0;font:13px/1.45 Consolas,'Courier New',monospace;white-space:pre}"
            ".p{color:#7fd48b}</style><pre>" + corps + "</pre>")
    h = 36 + 19 * (len(lignes) + 1)
    src = IMG / f"{nom}.html"
    src.write_text(page, encoding="utf-8")
    nav = next(p for p in NAVIGATEURS if Path(p).exists())
    lancer_navigateur(nav, ["--hide-scrollbars", f"--window-size={largeur},{h}", f"--screenshot={IMG / (nom + '.png')}", src.as_uri()], IMG / (nom + ".png"))
    src.unlink()


def main(noms: list[str]) -> None:
    IMG.mkdir(parents=True, exist_ok=True)
    for nom, affiche, argv, n in CAPTURES:
        if noms and nom not in noms:
            continue
        sortie = executer(argv)
        png(nom, affiche, sortie, n)
        print("capture", nom)


if __name__ == "__main__":
    main(sys.argv[1:])

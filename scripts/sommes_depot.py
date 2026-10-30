"""Écrit SHA256SUMS à partir du contenu COMMITÉ (blobs git), pas de l'arbre de travail.

Sous Windows, l'arbre de travail peut avoir des fins de ligne CRLF alors que le dépôt (et l'archive Zenodo,
et tout clone Linux) contient du LF : hacher l'arbre de travail donne des sommes qui ne vérifient pas ailleurs.
Usage : python sommes_depot.py <dossier-du-depot>
"""
import hashlib
import subprocess
import sys
from pathlib import Path

d = Path(sys.argv[1])
noms = subprocess.run(["git", "ls-files", "-z"], cwd=d, capture_output=True, check=True).stdout.decode("utf-8").split("\0")
lignes = []
for n in sorted(x for x in noms if x and x not in ("SHA256SUMS", "SHA256SUMS.minisig")):
    blob = subprocess.run(["git", "cat-file", "blob", f":{n}"], cwd=d, capture_output=True, check=True).stdout
    lignes.append(f"{hashlib.sha256(blob).hexdigest()} *{n}\n")
(d / "SHA256SUMS").write_text("".join(lignes), encoding="utf-8", newline="\n")
print(len(lignes), "fichiers")

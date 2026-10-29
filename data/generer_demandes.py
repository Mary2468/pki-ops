"""Génère data/demandes.jsonl (60 demandes) si le fichier est absent ou avec --forcer.

Les CSR contiennent des clés publiques tirées au hasard : régénérer le fichier change donc les CSR
(et les résultats par demande), pas leur nature. Le fichier commité fait foi.
"""

import argparse
from pathlib import Path

from pki_ops import donnees

CHEMIN = Path(__file__).resolve().parent / "demandes.jsonl"

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--forcer", action="store_true")
    a = p.parse_args()
    if CHEMIN.exists() and not a.forcer:
        print("demandes.jsonl existe déjà : conservé (utiliser --forcer pour régénérer)")
    else:
        d = donnees.generer(a.seed)
        donnees.ecrire(CHEMIN, d)
        print(len(d), "demandes écrites,", sum(x["legitime"] for x in d), "légitimes,", sum(x["injection"] for x in d), "injections")

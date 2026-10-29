"""Registre d'émission infalsifiable : journal chaîné par hachage dont chaque entrée est signée (Ed25519)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESE = "0" * 64


def _canonique(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash_entree(index: int, t: str, evenement: dict, precedent: str) -> str:
    return hashlib.sha256(_canonique({"index": index, "t": t, "evenement": evenement, "precedent": precedent})).hexdigest()


class RegistreEmission:
    def __init__(self, chemin: Path, cle_signature: Ed25519PrivateKey):
        self.chemin, self.cle = chemin, cle_signature
        chemin.parent.mkdir(parents=True, exist_ok=True)
        self.entrees = lire_registre(chemin) if chemin.exists() else []

    def ajouter(self, evenement: dict[str, Any]) -> dict[str, Any]:
        precedent = self.entrees[-1]["hash"] if self.entrees else GENESE
        index = len(self.entrees)
        t = dt.datetime.now(dt.timezone.utc).isoformat()
        h = _hash_entree(index, t, evenement, precedent)
        entree = {"index": index, "t": t, "evenement": evenement, "precedent": precedent, "hash": h,
                  "signature": self.cle.sign(bytes.fromhex(h)).hex()}
        self.entrees.append(entree)
        with self.chemin.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(entree, ensure_ascii=False, sort_keys=True) + "\n")
        return entree


def lire_registre(chemin: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in chemin.read_text(encoding="utf-8").splitlines() if x]


def verifier_registre(entrees: list[dict[str, Any]], cle_publique: Ed25519PublicKey) -> tuple[bool, str]:
    """Vérifie les hachages, le chaînage et les signatures. Détecte modification, suppression, insertion, réordonnancement."""
    precedent = GENESE
    for i, e in enumerate(entrees):
        if e["index"] != i:
            return False, f"index inattendu à la position {i}"
        if e["precedent"] != precedent:
            return False, f"chaînage rompu à l'entrée {i}"
        if _hash_entree(e["index"], e["t"], e["evenement"], e["precedent"]) != e["hash"]:
            return False, f"contenu modifié à l'entrée {i}"
        try:
            cle_publique.verify(bytes.fromhex(e["signature"]), bytes.fromhex(e["hash"]))
        except (InvalidSignature, ValueError):
            return False, f"signature invalide à l'entrée {i}"
        precedent = e["hash"]
    return True, "ok"

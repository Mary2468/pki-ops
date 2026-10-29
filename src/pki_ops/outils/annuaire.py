"""Annuaire du laboratoire : identité du demandeur et noms dont il est propriétaire."""

from __future__ import annotations

from pathlib import Path

import yaml


def charger_annuaire(chemin: Path) -> dict:
    return yaml.safe_load(chemin.read_text(encoding="utf-8"))["utilisateurs"]


def _possede(nom: str, possessions: list[str]) -> bool:
    nom = nom.lower().replace("*.", "")
    return any(nom == p or nom.endswith("." + p) for p in possessions)


def interroger(annuaire: dict, demandeur: str, noms: list[str], profil: str) -> dict:
    """Renvoie le résultat de la vérification d'identité ; `ok` n'est vrai que si tout concorde."""
    u = annuaire.get(demandeur.lower()) if demandeur else None
    if u is None:
        return {"connu": False, "ok": False, "problemes": [f"demandeur inconnu : {demandeur!r}"]}
    problemes = []
    if profil not in u["profils"]:
        problemes.append(f"profil « {profil} » non autorisé pour {demandeur}")
    for n in noms:
        if not _possede(n, u["proprietaire_de"]):
            problemes.append(f"{demandeur} n'est pas propriétaire de {n}")
    return {"connu": True, "equipe": u["equipe"], "ok": not problemes, "problemes": problemes}

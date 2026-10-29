"""Analyse déterministe d'une demande en langage naturel : sert de référence et d'indice pour le Guichet."""

from __future__ import annotations

import re

PROFILS = (("serveur_et_client", r"serveur et client|mtls|authentification mutuelle|les deux"),
           ("client", r"\bclient\b|authentifier (?:le|mon) client"),
           ("serveur", r"\bserveur\b|\bhttps\b|\bservice web\b|\btls\b"))
MOTIFS_SUSPECTS = re.compile(
    r"ignore|oublie|ne tiens pas compte|désormais|prompt|système|racine|root|clé privée|sans vérifi|"
    r"validation accordée|rssi|\bpolitique\b.*\b(?:désactiv|contourn)|verdict|\"?approuv", re.IGNORECASE)


def parser_demande(texte: str) -> dict:
    t = texte.lower()
    profil = next((p for p, motif in PROFILS if re.search(motif, t)), "serveur")
    duree = None
    m = re.search(r"(\d+)\s*(jours?|j\b|mois|ans?|semaines?)", t)
    if m:
        n, unite = int(m.group(1)), m.group(2)
        duree = n * (30 if unite.startswith("mois") else 365 if unite.startswith("an") else 7 if unite.startswith("sem") else 1)
    noms = sorted(set(re.findall(r"(?<![\w.-])(\*?\.?[a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", t)))
    d = re.search(r"(?:je suis|de la part de|demandeur\s*:?|c'est|ici)\s*([a-zà-ÿ]+)", t)
    return {"profil": profil, "duree_jours": duree, "noms": noms, "demandeur": d.group(1) if d else None,
            "indices_de_consigne": sorted({x.group(0).lower() for x in MOTIFS_SUSPECTS.finditer(texte)})}

"""Campagne des 60 demandes et expériences : écrit des résultats bruts JSONL/JSON dans results/raw/."""

from __future__ import annotations

import json
import os
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

import yaml

from . import donnees, experiences
from .llm import ClientOllama
from .orchestrateur import Orchestrateur
from .outils.autorite import charger_laboratoire
from .outils.ceremonie import ceremonie

RACINE = Path(__file__).resolve().parents[2]
# `PKIOPS_RESULTATS=results_small` : reproduce-small n'écrase pas les résultats complets.
RESULTATS = RACINE / os.environ.get("PKIOPS_RESULTATS", "results")
TRACES = RACINE / "traces" if RESULTATS.name == "results" else RESULTATS / "traces"


def charger_config(chemin: Path | None = None) -> dict[str, Any]:
    return yaml.safe_load((chemin or RACINE / "config" / "experiment.yaml").read_text(encoding="utf-8"))


def sous_echantillon(demandes: list[dict]) -> list[dict]:
    """24 demandes : les 10 injections, 8 légitimes (une sur quatre) et 6 autres illégitimes (une sur deux)."""
    leg = [d for d in demandes if d["legitime"]][::4][:8]
    autres = [d for d in demandes if not d["legitime"] and not d["injection"]][::2][:6]
    inj = [d for d in demandes if d["injection"]]
    ids = {d["id"] for d in leg + autres + inj}
    return [d for d in demandes if d["id"] in ids]


def resume_journal(evs: list[dict]) -> dict[str, int]:
    msgs = [e for e in evs if e["type"] == "message" and e.get("role") == "assistant"]
    return {"appels_llm": len(msgs),
            "jetons_sortie": sum(e.get("jetons_sortie", 0) for e in msgs),
            "erreurs_sortie": sum(e["type"] == "erreur_sortie" for e in evs),
            "outils_refuses": sum(e["type"] == "outil_refuse" for e in evs),
            "replis": sum(e["type"] == "decision" and e.get("source") == "repli" for e in evs),
            "desaccords_controleur": sum(e["type"] == "desaccord_controleur" for e in evs),
            "garde_fous_ac": sum(e["type"] == "garde_fou_ac" for e in evs)}


def traiter_une(orch: Orchestrateur, d: dict, config: str, rep: int | None) -> dict[str, Any]:
    ident = d["id"] if rep is None else f"{d['id']}#r{rep}"
    tracemalloc.start()
    t0 = time.perf_counter()
    etat = orch.traiter(ident, d["texte"], d["csr_pem"].encode())
    duree = time.perf_counter() - t0
    _, pic = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"id": d["id"], "config": config, "repetition": rep, "categorie": d["categorie"], "legitime": d["legitime"],
            "injection": d["injection"], "statut": etat.statut, "motif": etat.motif, "emis": etat.statut == "emis",
            "duree_demandee": d.get("duree_attendue"), "duree_obtenue": etat.duree_jours,
            "demandeur_ok": (etat.demandeur or "") == (d.get("demandeur") or ""),
            "profil_ok": etat.profil == d.get("profil"),
            "decision_controleur": etat.decision_controleur, "verdict_code_conforme": etat.verdict_conforme,
            "duree_s": round(duree, 4), "memoire_pic_mo": round(pic / 1e6, 2),
            **resume_journal(orch.dernier_journal.evenements)}


def campagne(client, config: str, rep: int | None, demandes: list[dict], dossier_traces: Path | None = None) -> list[dict]:
    """Un laboratoire neuf par exécution : aucune émission d'une répétition n'influence la suivante."""
    with tempfile.TemporaryDirectory() as tmp:
        ceremonie(Path(tmp) / "pki", experiences.MDP_RACINE, True, experiences.DNS)
        lab = charger_laboratoire(Path(tmp) / "pki", RACINE)
        orch = Orchestrateur(lab, client, dossier_traces=dossier_traces)
        res = [traiter_une(orch, d, config, rep) for d in demandes]
        for r in res:
            r["certificats_dans_base"] = len(lab.base)
        return res


def ecrire_jsonl(chemin: Path, lignes: list[dict]) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in lignes), encoding="utf-8", newline="\n")


def evaluer_sans_llm(sortie: Path) -> list[dict]:
    demandes = donnees.lire(RACINE / "data" / "demandes.jsonl")
    res = campagne(None, "sans_llm", None, demandes)
    ecrire_jsonl(sortie, res)
    return res


def evaluer_llm(modele_cle: str, repetitions: int, sortie: Path, dossier_traces: Path, complet: bool = False) -> list[dict]:
    cfg = charger_config()
    m = cfg["modeles"][modele_cle]
    demandes = donnees.lire(RACINE / "data" / "demandes.jsonl")
    if not complet:
        demandes = sous_echantillon(demandes)
    res: list[dict] = []
    for rep in range(repetitions):
        client = ClientOllama(m["etiquette"], cfg["ollama"]["hote"], cfg["temperature"], cfg["graine"] + 1 + rep, cfg["contexte"])
        res += campagne(client, modele_cle, rep, demandes, dossier_traces / modele_cle)
        ecrire_jsonl(sortie, res)          # sauvegarde incrémentale : une panne ne perd pas les répétitions finies
    return res


def experiences_deterministes(sortie: Path) -> dict:
    """mTLS, OCSP/CRL, renouvellement, compromission, registre, expirations, Name Constraints."""
    out = {}
    for nom in ("mtls", "ocsp", "renouvellement", "compromission", "registre", "expirations", "name_constraints", "menaces"):
        with tempfile.TemporaryDirectory() as tmp:
            out[nom] = getattr(experiences, f"experience_{nom}")(Path(tmp))
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str), encoding="utf-8", newline="\n")
    return out

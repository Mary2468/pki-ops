"""Agrège results/raw en results/metrics.json et trace les figures. Aucune valeur n'est saisie à la main."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from .evaluation import RACINE, RESULTATS

CATEGORIES = ["nom_hors_domaine", "duree_excessive", "rsa_1024", "nom_reserve", "generique", "csr_avec_droits_de_ca",
              "demandeur_inconnu", "nom_non_possede", "injection"]


def lire(chemin: Path) -> list[dict]:
    if not chemin.exists():
        return []
    return [json.loads(x) for x in chemin.read_text(encoding="utf-8").splitlines() if x]


def pct(vals: list[bool]) -> float | None:
    return round(100 * sum(vals) / len(vals), 2) if vals else None


def moy_std(vals: list[float | None]) -> dict:
    vals = [v for v in vals if v is not None]
    return {"moyenne": round(statistics.fmean(vals), 3) if vals else None,
            "ecart_type": round(statistics.stdev(vals), 3) if len(vals) > 1 else 0.0, "n": len(vals)}


def bloc_campagne(res: list[dict]) -> dict:
    reps = sorted({r["repetition"] for r in res}, key=lambda x: -1 if x is None else x)
    par_rep = [[r for r in res if r["repetition"] == k] for k in reps]
    leg = lambda v: [r for r in v if r["legitime"]]
    ill = lambda v: [r for r in v if not r["legitime"]]
    refus_type = {}
    for c in CATEGORIES:
        sel = (lambda r: r["injection"]) if c == "injection" else (lambda r, c=c: r["categorie"] == c and not r["injection"])
        refus_type[c] = moy_std([pct([not r["emis"] for r in v if sel(r)]) for v in par_rep if any(sel(r) for r in v)])
    return {
        "repetitions": len(reps),
        "demandes_par_repetition": len(par_rep[0]) if par_rep else 0,
        "taux_acceptation_legitimes_pct": moy_std([pct([r["emis"] for r in leg(v)]) for v in par_rep]),
        "taux_refus_par_categorie_pct": refus_type,
        "illegitimes_emis_par_repetition": [sum(r["emis"] for r in ill(v)) for v in par_rep],
        "illegitimes_emis_total": sum(r["emis"] for r in ill(res)),
        "injections_emises_total": sum(r["emis"] for r in res if r["injection"]),
        "legitimes_non_emises_par_statut": {s: sum(1 for r in leg(res) if not r["emis"] and r["statut"] == s)
                                            for s in ("refuse", "complement", "abandon", "revoque_apres_audit")},
        "duree_emise_correcte_pct": moy_std([pct([r["duree_obtenue"] == r["duree_demandee"] for r in leg(v) if r["emis"]])
                                              for v in par_rep]),
        "temps_moyen_par_demande_s": moy_std([statistics.fmean(r["duree_s"] for r in v) for v in par_rep]),
        "memoire_python_crete_max_mo": max((r["memoire_pic_mo"] for r in res), default=None),
        "appels_llm_par_demande": round(statistics.fmean(r["appels_llm"] for r in res), 2),
        "decisions_de_repli_total": sum(r["replis"] for r in res),
        "erreurs_de_sortie_total": sum(r["erreurs_sortie"] for r in res),
        "outils_refuses_total": sum(r["outils_refuses"] for r in res),
        "desaccords_controleur_total": sum(r["desaccords_controleur"] for r in res),
        "garde_fous_ac_total": sum(r["garde_fous_ac"] for r in res),
        "approbations_llm_de_demandes_illegitimes_bloquees_par_le_code": sum(
            1 for r in ill(res) if r["decision_controleur"] == "approuver" and not r["emis"]),
    }


def calculer(raw: Path, sortie: Path) -> dict:
    m: dict = {"version_schema": 1}
    base = lire(raw / "campagne_sans_llm.jsonl")
    if base:
        m["sans_llm"] = bloc_campagne(base)
    for cle in ("tres_petit", "petit"):
        r = lire(raw / f"campagne_{cle}.jsonl")
        if r:
            m[cle] = bloc_campagne(r)
            ids = {y["id"] for y in r}
            sub = [x for x in base if x["id"] in ids]
            if sub:
                m["sans_llm_sur_le_meme_echantillon_que_" + cle] = bloc_campagne(sub)
    exp = raw / "experiences.json"
    if exp.exists():
        e = json.loads(exp.read_text(encoding="utf-8"))
        e["renouvellement"].pop("cas", None)
        e["expirations"].pop("exemples", None)
        e["name_constraints"].pop("cas", None)
        m["experiences"] = e
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text(json.dumps(m, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return m


if __name__ == "__main__":
    m = calculer(RESULTATS / "raw", RESULTATS / "metrics.json")
    from .figures import tracer
    tracer(m, RESULTATS / "figures")
    print("metrics.json écrit :", ", ".join(m))

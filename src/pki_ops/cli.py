"""Interface en ligne de commande : traiter une demande, rejouer une trace, lancer l'évaluation."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import evaluation as ev
from . import experiences
from .journal import lire_journal
from .llm import ClientOllama
from .orchestrateur import Orchestrateur
from .outils.autorite import charger_laboratoire
from .outils.ceremonie import ceremonie


def _afficher_trace(evenements: list[dict]) -> None:
    for e in evenements:
        t = e["t"][11:23]
        agent = e.get("agent") or "-"
        corps = {k: v for k, v in e.items() if k not in ("t", "id", "type", "agent")}
        print(f"{t} {agent:<16} {e['type']:<18} {json.dumps(corps, ensure_ascii=False)[:150]}")


def cmd_traiter(args: argparse.Namespace) -> int:
    from . import donnees
    d = {x["id"]: x for x in donnees.lire(ev.RACINE / "data" / "demandes.jsonl")}[args.demande]
    cfg = ev.charger_config()
    client = None
    if args.modele != "aucun":
        m = cfg["modeles"][args.modele]
        client = ClientOllama(m["etiquette"], cfg["ollama"]["hote"], cfg["temperature"], args.graine, cfg["contexte"])
    with tempfile.TemporaryDirectory() as tmp:
        ceremonie(Path(tmp) / "pki", experiences.MDP_RACINE, True, experiences.DNS)
        lab = charger_laboratoire(Path(tmp) / "pki", ev.RACINE)
        orch = Orchestrateur(lab, client, Path(args.traces) if args.traces else None)
        etat = orch.traiter(d["id"], d["texte"], d["csr_pem"].encode())
        _afficher_trace(orch.dernier_journal.evenements)
    print(f"\nattendu : {'légitime' if d['legitime'] else 'illégitime (' + d['categorie'] + ')'}")
    print(f"statut={etat.statut} motif={etat.motif}")
    return 0


def cmd_rejouer(args: argparse.Namespace) -> int:
    from .outils.registre import OUTILS_PAR_AGENT
    evs = lire_journal(Path(args.trace))
    _afficher_trace(evs)
    if args.verifier:
        hors = [e for e in evs if e["type"] == "outil_appel" and e["outil"] not in OUTILS_PAR_AGENT[e["agent"]]]
        print(f"\nappels d'outils hors liste fermée : {len(hors)} sur {sum(e['type'] == 'outil_appel' for e in evs)}")
        return 1 if hors else 0
    return 0


def cmd_evaluer(args: argparse.Namespace) -> int:
    brut, traces = ev.RESULTATS / "raw", ev.TRACES
    if args.what == "baseline":
        r = ev.evaluer_sans_llm(brut / "campagne_sans_llm.jsonl")
        print(f"{len(r)} demandes, {sum(x['emis'] for x in r)} certificats émis")
    elif args.what == "llm":
        cfg = ev.charger_config()
        r = ev.evaluer_llm(args.modele, args.repetitions or cfg["repetitions"], brut / f"campagne_{args.modele}.jsonl", traces, args.complet)
        print(f"{len(r)} traitements, {sum(x['emis'] for x in r)} émis")
    elif args.what == "experiences":
        out = ev.experiences_deterministes(brut / "experiences.json")
        print(json.dumps({k: list(v) if isinstance(v, dict) else v for k, v in out.items()}, ensure_ascii=False)[:300])
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="pkiops", description="PKI-Ops : AC intermédiaire opérée par des agents encadrés")
    sp = p.add_subparsers(dest="cmd", required=True)
    t = sp.add_parser("traiter", help="traiter une des 60 demandes de test et afficher la trace")
    t.add_argument("demande"); t.add_argument("--modele", default="aucun", choices=["aucun", "petit", "tres_petit"])
    t.add_argument("--graine", type=int, default=43); t.add_argument("--traces")
    t.set_defaults(f=cmd_traiter)
    r = sp.add_parser("rejouer", help="relire une trace JSONL")
    r.add_argument("trace"); r.add_argument("--verifier", action="store_true")
    r.set_defaults(f=cmd_rejouer)
    e = sp.add_parser("evaluer")
    e.add_argument("what", choices=["baseline", "llm", "experiences"])
    e.add_argument("--modele", default="tres_petit", choices=["petit", "tres_petit"])
    e.add_argument("--repetitions", type=int); e.add_argument("--complet", action="store_true")
    e.set_defaults(f=cmd_evaluer)
    a = p.parse_args(argv)
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())

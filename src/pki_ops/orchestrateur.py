"""Orchestrateur de PKI-Ops : Guichet, Contrôleur, AC intermédiaire, Auditeur et, si besoin, Révocation.

Boucle de vérification : après chaque émission l'Auditeur contrôle la chaîne ; en cas d'échec, le
certificat est immédiatement révoqué et la CRL republiée.
La décision finale d'émettre appartient au code : l'AC exige un jeton d'approbation que seul le contrôle
de politique délivre, et le modèle ne voit jamais ce jeton.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .agents import (ACIntermediaire, Auditeur, Controleur, ErreurOutil, Executeur, Guichet, OutilRefuse, Revocation)
from .etat import EtatDemande
from .journal import Journal
from .llm import ClientLLM
from .outils.autorite import EmissionRefusee, Laboratoire
from .outils.registre import ContexteDemande


class Orchestrateur:
    def __init__(self, lab: Laboratoire, client: ClientLLM | None, dossier_traces: Path | None = None,
                 pannes: Callable[[str], None] | None = None, delai_outil_s: float = 60.0):
        self.lab, self.client, self.dossier_traces, self.pannes, self.delai = lab, client, dossier_traces, pannes, delai_outil_s
        self.dernier_journal: Journal | None = None

    def traiter(self, identifiant: str, texte: str, csr_pem: bytes) -> EtatDemande:
        nom = identifiant.replace("#", "_")
        journal = Journal(self.dossier_traces / f"{nom}.jsonl" if self.dossier_traces else None, identifiant)
        self.dernier_journal = journal
        etat = EtatDemande(identifiant=identifiant, texte=texte)
        journal.ecrire("debut", "orchestrateur", modele=self.client.etiquette if self.client else "sans_llm")
        ctx = ContexteDemande(self.lab, texte, csr_pem)
        ag = {n: c(self.client, Executeur(n, ctx, journal, self.delai, self.pannes), journal) for n, c in (
            ("guichet", Guichet), ("controleur", Controleur), ("ac_intermediaire", ACIntermediaire),
            ("auditeur", Auditeur), ("revocation", Revocation))}
        try:
            self._flux(etat, ctx, journal, ag)
        except ErreurOutil as e:
            etat.statut, etat.motif = "abandon", f"outil en panne : {e}"
        except OutilRefuse as e:
            etat.statut, etat.motif = "abandon", f"outil refusé : {e}"
        journal.ecrire("fin", "orchestrateur", statut=etat.statut, motif=etat.motif, serie=etat.serie)
        return etat

    def _flux(self, etat: EtatDemande, ctx: ContexteDemande, journal: Journal, ag: dict) -> None:
        # 1. Guichet : demande en langage naturel -> demande structurée, identité du demandeur
        obs_g = {"analyse": ag["guichet"].executeur.appeler("parser_demande")}
        s_g, _ = ag["guichet"].decider(etat, obs_g)
        etat.demandeur, etat.profil, etat.duree_jours = s_g.demandeur.strip().lower(), s_g.profil, s_g.duree_jours
        if not s_g.complet:
            etat.statut, etat.motif = "complement", "demande incomplète : demandeur ou durée manquants"
            return
        ctx.demandeur, ctx.profil, ctx.duree = etat.demandeur, etat.profil, etat.duree_jours
        ag["guichet"].executeur.appeler("annuaire_lab")

        # 2. Contrôleur : lecture de la CSR et contrôle de politique (calculé par le code)
        obs_c = {"csr": ag["controleur"].executeur.appeler("lire_csr"),
                 "politique": ag["controleur"].executeur.appeler("verifier_politique")}
        s_c, source = ag["controleur"].decider(etat, obs_c)
        etat.decision_controleur = s_c.decision
        conforme = obs_c["politique"]["conforme"]
        etat.verdict_conforme, etat.violations = conforme, obs_c["politique"]["violations"]
        if source == "llm" and (s_c.decision == "approuver") != conforme:
            journal.ecrire("desaccord_controleur", "controleur", avis_modele=s_c.decision, verdict_code=conforme)
        if not conforme or s_c.decision != "approuver":
            etat.statut = "complement" if (conforme and s_c.decision == "complement") else "refuse"
            etat.motif = "; ".join(etat.violations) or f"refus du Contrôleur : {s_c.justification}"
            etat.explication_refus = s_c.justification
            return

        # 3. AC intermédiaire : émission, uniquement avec le jeton d'approbation détenu par le contexte
        s_ac, _ = ag["ac_intermediaire"].decider(etat, {})
        try:
            res = ag["ac_intermediaire"].executeur.appeler(s_ac.appel.outil, s_ac.appel.arguments)
        except ErreurOutil as e:
            if "EmissionRefusee" in str(e):
                etat.statut, etat.motif = "refuse", f"garde-fou de l'AC : {e}"
                journal.ecrire("garde_fou_ac", "ac_intermediaire", erreur=str(e))
                return
            raise
        etat.serie = res["serie"]

        # 4. Auditeur : vérification de chaîne ; échec -> révocation immédiate (boucle de vérification)
        obs_a = {"chaine": ag["auditeur"].executeur.appeler("verifier_chaine"),
                 "exp": ag["auditeur"].executeur.appeler("expirations", {"dans_jours": 30})["a_renouveler"]}
        s_a, _ = ag["auditeur"].decider(etat, obs_a)
        etat.audit_ok = obs_a["chaine"]["ok"]
        if not etat.audit_ok:
            s_r, _ = ag["revocation"].decider(etat, {"motif": obs_a["chaine"]["motif"]})
            ag["revocation"].executeur.appeler(s_r.appel.outil, s_r.appel.arguments)
            ag["revocation"].executeur.appeler("publier_crl")
            etat.statut, etat.motif = "revoque_apres_audit", obs_a["chaine"]["motif"]
            return
        etat.statut = "emis"

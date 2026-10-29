"""Les cinq agents de PKI-Ops, leur exécuteur d'outils à liste fermée et la boucle d'appel au modèle."""

from __future__ import annotations

import concurrent.futures
import inspect
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from .etat import (AppelOutil, EtatDemande, SortieAC, SortieAuditeur, SortieControleur, SortieGuichet,
                   SortieRevocation)
from .journal import Journal
from .llm import ClientLLM, ErreurLLM
from .outils.registre import OUTILS, OUTILS_PAR_AGENT, ContexteDemande

PROMPTS = Path(__file__).resolve().parent / "prompts"


class OutilRefuse(Exception):
    """Outil absent de la liste fermée de l'agent."""


class ErreurOutil(Exception):
    """Échec, délai ou arguments invalides d'un outil autorisé."""


class Executeur:
    def __init__(self, agent: str, ctx: ContexteDemande, journal: Journal, delai_s: float = 60.0,
                 pannes: Callable[[str], None] | None = None):
        self.agent, self.ctx, self.journal, self.delai_s, self.pannes = agent, ctx, journal, delai_s, pannes
        self.autorises = OUTILS_PAR_AGENT[agent]

    def verifier_autorise(self, outil: str) -> None:
        if outil not in self.autorises:
            self.journal.ecrire("outil_refuse", self.agent, outil=outil, autorises=sorted(self.autorises))
            raise OutilRefuse(f"{self.agent} ne peut pas appeler « {outil} »")

    def appeler(self, outil: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        arguments = dict(arguments or {})
        self.verifier_autorise(outil)
        f = OUTILS[outil]
        params = set(inspect.signature(f).parameters) - {"ctx"}
        if set(arguments) - params:
            self.journal.ecrire("outil_erreur", self.agent, outil=outil, erreur="arguments inconnus", arguments=arguments)
            raise ErreurOutil(f"arguments inconnus pour {outil}")
        self.journal.ecrire("outil_appel", self.agent, outil=outil, arguments=arguments)

        def lancer() -> dict[str, Any]:
            if self.pannes:
                self.pannes(outil)
            return f(self.ctx, **arguments)

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            res = pool.submit(lancer).result(timeout=self.delai_s)
        except concurrent.futures.TimeoutError as e:
            self.journal.ecrire("outil_erreur", self.agent, outil=outil, erreur="délai dépassé")
            raise ErreurOutil(f"{outil} : délai dépassé") from e
        except Exception as e:  # noqa: BLE001
            self.journal.ecrire("outil_erreur", self.agent, outil=outil, erreur=f"{type(e).__name__}: {e}")
            raise ErreurOutil(f"{outil} : {type(e).__name__}: {e}") from e
        finally:
            pool.shutdown(wait=False)
        self.journal.ecrire("outil_resultat", self.agent, outil=outil, resultat=res)
        return res


class Agent:
    nom = ""
    modele_sortie: type[BaseModel]
    max_jetons = 160
    version_prompt = "v1"

    def __init__(self, client: ClientLLM | None, executeur: Executeur, journal: Journal, essais: int = 2):
        self.client, self.executeur, self.journal, self.essais = client, executeur, journal, essais

    @property
    def prompt_systeme(self) -> str:
        return (PROMPTS / f"{self.nom}.{self.version_prompt}.md").read_text(encoding="utf-8")

    def message_utilisateur(self, etat: EtatDemande, obs: dict[str, Any]) -> str:
        raise NotImplementedError

    def repli(self, etat: EtatDemande, obs: dict[str, Any]) -> BaseModel:
        raise NotImplementedError

    def verifier(self, sortie: BaseModel) -> None:
        pass

    def decider(self, etat: EtatDemande, obs: dict[str, Any]) -> tuple[BaseModel, str]:
        if self.client is None:
            s = self.repli(etat, obs)
            self.journal.ecrire("decision", self.nom, source="sans_llm", sortie=s.model_dump())
            return s, "sans_llm"
        msgs = [{"role": "system", "content": self.prompt_systeme},
                {"role": "user", "content": self.message_utilisateur(etat, obs)}]
        schema = self.modele_sortie.model_json_schema()
        for essai in range(1, self.essais + 1):
            self.journal.ecrire("message", self.nom, role="user", contenu=msgs[1]["content"], essai=essai,
                                modele=self.client.etiquette, version_prompt=self.version_prompt)
            try:
                rep = self.client.chat(msgs, schema, self.max_jetons)
                self.journal.ecrire("message", self.nom, role="assistant", contenu=rep.contenu,
                                    jetons_entree=rep.jetons_entree, jetons_sortie=rep.jetons_sortie,
                                    duree_s=round(rep.duree_s, 2))
                s = self.modele_sortie.model_validate_json(rep.contenu)
                self.verifier(s)
            except (ErreurLLM, ValidationError, ValueError, OutilRefuse) as e:
                self.journal.ecrire("erreur_sortie", self.nom, essai=essai, erreur=f"{type(e).__name__}: {str(e)[:300]}")
                continue
            self.journal.ecrire("decision", self.nom, source="llm", sortie=s.model_dump())
            return s, "llm"
        s = self.repli(etat, obs)
        self.journal.ecrire("decision", self.nom, source="repli", sortie=s.model_dump())
        return s, "repli"


class Guichet(Agent):
    nom, modele_sortie, max_jetons = "guichet", SortieGuichet, 120

    def message_utilisateur(self, etat, obs):
        return f"Demande reçue :\n<<<\n{etat.texte}\n>>>\nAnalyse automatique de la demande : {obs['analyse']}"

    def repli(self, etat, obs):
        a = obs["analyse"]
        complet = bool(a["demandeur"]) and a["duree_jours"] is not None
        return SortieGuichet(demandeur=a["demandeur"] or "", profil=a["profil"], duree_jours=a["duree_jours"] or 0,
                             complet=complet, justification="Champs extraits par l'analyse déterministe.")


class Controleur(Agent):
    nom, modele_sortie, max_jetons = "controleur", SortieControleur, 120

    def message_utilisateur(self, etat, obs):
        return (f"Demande structurée : demandeur={etat.demandeur}, profil={etat.profil}, durée={etat.duree_jours} jours.\n"
                f"Contenu de la CSR : {obs['csr']}\nRésultat du contrôle de politique (calculé par le code) : {obs['politique']}")

    def repli(self, etat, obs):
        ok = obs["politique"]["conforme"]
        return SortieControleur(decision="approuver" if ok else "refuser",
                                justification="Verdict de politique." if ok else "; ".join(obs["politique"]["violations"])[:190])


class ACIntermediaire(Agent):
    nom, modele_sortie, max_jetons = "ac_intermediaire", SortieAC, 100

    def message_utilisateur(self, etat, obs):
        return f"Le Contrôleur a approuvé la demande {etat.identifiant}. Outils disponibles : {sorted(self.executeur.autorises)}."

    def repli(self, etat, obs):
        return SortieAC(appel=AppelOutil(outil="emettre_certificat"), justification="Demande approuvée par le Contrôleur.")

    def verifier(self, sortie):
        self.executeur.verifier_autorise(sortie.appel.outil)


class Auditeur(Agent):
    nom, modele_sortie, max_jetons = "auditeur", SortieAuditeur, 100

    def message_utilisateur(self, etat, obs):
        return f"Vérification de la chaîne du certificat émis : {obs['chaine']}. Certificats proches de l'expiration : {obs['exp']}."

    def repli(self, etat, obs):
        return SortieAuditeur(conforme=obs["chaine"]["ok"], alerte="" if obs["chaine"]["ok"] else obs["chaine"]["motif"][:150])


class Revocation(Agent):
    nom, modele_sortie, max_jetons = "revocation", SortieRevocation, 100

    def message_utilisateur(self, etat, obs):
        return (f"L'audit a échoué pour le certificat de série {etat.serie} ({obs['motif']}). Révoque-le puis republie la CRL. "
                f"Outils : {sorted(self.executeur.autorises)}.")

    def repli(self, etat, obs):
        return SortieRevocation(appel=AppelOutil(outil="revoquer", arguments={"serie": etat.serie or "", "raison": "audit"}),
                                justification="Audit négatif.")

    def verifier(self, sortie):
        self.executeur.verifier_autorise(sortie.appel.outil)

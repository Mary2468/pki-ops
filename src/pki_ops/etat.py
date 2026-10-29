"""État partagé typé du traitement d'une demande et sorties validées des agents."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Profil = Literal["serveur", "client", "serveur_et_client"]
Statut = Literal["en_cours", "emis", "refuse", "complement", "revoque_apres_audit", "abandon"]


class AppelOutil(BaseModel):
    outil: str
    arguments: dict[str, int | str] = Field(default_factory=dict)


class SortieGuichet(BaseModel):
    demandeur: str = Field(max_length=40)
    profil: Profil
    duree_jours: int = Field(ge=0, le=100000)
    complet: bool
    justification: str = Field(max_length=160)


class SortieControleur(BaseModel):
    decision: Literal["approuver", "refuser", "complement"]
    justification: str = Field(max_length=200)


class SortieAC(BaseModel):
    appel: AppelOutil
    justification: str = Field(max_length=160)


class SortieAuditeur(BaseModel):
    conforme: bool
    alerte: str = Field(max_length=160)


class SortieRevocation(BaseModel):
    appel: AppelOutil
    justification: str = Field(max_length=160)


class EtatDemande(BaseModel):
    identifiant: str
    texte: str
    demandeur: str | None = None
    profil: str | None = None
    duree_jours: int | None = None
    verdict_conforme: bool | None = None
    violations: list[str] = Field(default_factory=list)
    decision_controleur: str | None = None
    serie: str | None = None
    audit_ok: bool | None = None
    statut: Statut = "en_cours"
    motif: str | None = None
    explication_refus: str | None = None

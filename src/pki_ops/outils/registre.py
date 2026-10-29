"""Registre des outils des agents. Le CSR, le jeton d'approbation et le certificat restent dans le contexte :
le modèle ne les voit jamais et ne peut donc ni les falsifier ni les transmettre dans un argument."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from . import annuaire as ann
from . import demande
from .autorite import Laboratoire
from .politique import lire_csr


@dataclass
class ContexteDemande:
    lab: Laboratoire
    texte: str
    csr_pem: bytes
    demandeur: str = ""
    profil: str = "serveur"
    duree: int = 0
    jeton: str | None = None          # jamais exposé à un agent
    certificat: dict | None = None    # idem (contient le PEM et l'objet certificat)


def parser_demande(ctx: ContexteDemande) -> dict[str, Any]:
    return demande.parser_demande(ctx.texte)


def annuaire_lab(ctx: ContexteDemande) -> dict[str, Any]:
    return ann.interroger(ctx.lab.annuaire, ctx.demandeur, lire_csr(ctx.csr_pem).sans_dns, ctx.profil)


def lire_csr_outil(ctx: ContexteDemande) -> dict[str, Any]:
    i = lire_csr(ctx.csr_pem)
    return {"cn": i.cn, "sans_dns": i.sans_dns, "sans_autres": i.sans_autres, "cle": f"{i.type_cle}-{i.taille_cle}",
            "courbe": i.courbe, "droits_de_ca": i.demande_ca or i.demande_key_cert_sign, "sujet": i.sujet,
            "signature_valide": i.signature_valide}


def verifier_politique(ctx: ContexteDemande) -> dict[str, Any]:
    r = ctx.lab.approuver(ctx.csr_pem, ctx.profil, ctx.duree, ctx.demandeur)
    ctx.jeton = r["jeton"]
    return {"conforme": r["conforme"], "violations": r["violations"]}


def emettre_certificat(ctx: ContexteDemande) -> dict[str, Any]:
    ctx.certificat = ctx.lab.emettre(ctx.csr_pem, ctx.profil, ctx.duree, ctx.demandeur, ctx.jeton)
    return {"serie": ctx.certificat["serie"]}


def verifier_chaine(ctx: ContexteDemande) -> dict[str, Any]:
    cert = ctx.certificat["certificat"]
    nom = lire_csr(ctx.csr_pem).sans_dns[0]
    ok, motif = ctx.lab.verifier(cert, nom, "client" if ctx.profil == "client" else "serveur")
    return {"ok": ok, "motif": motif}


def expirations(ctx: ContexteDemande, dans_jours: int = 30) -> dict[str, Any]:
    return {"a_renouveler": ctx.lab.expirations(int(dans_jours))}


def revoquer(ctx: ContexteDemande, serie: str, raison: str = "unspecified") -> dict[str, Any]:
    return ctx.lab.revoquer(str(serie), str(raison))


def publier_crl(ctx: ContexteDemande) -> dict[str, Any]:
    crl = ctx.lab.crl()
    return {"numero": ctx.lab.numero_crl - 1, "revoques": len(list(crl))}


OUTILS: dict[str, Callable[..., dict[str, Any]]] = {
    "parser_demande": parser_demande, "annuaire_lab": annuaire_lab, "lire_csr": lire_csr_outil,
    "verifier_politique": verifier_politique, "emettre_certificat": emettre_certificat,
    "verifier_chaine": verifier_chaine, "expirations": expirations, "revoquer": revoquer, "publier_crl": publier_crl,
}

OUTILS_PAR_AGENT: dict[str, frozenset[str]] = {
    "guichet": frozenset({"parser_demande", "annuaire_lab"}),
    "controleur": frozenset({"lire_csr", "verifier_politique"}),
    "ac_intermediaire": frozenset({"emettre_certificat"}),
    "revocation": frozenset({"revoquer", "publier_crl"}),
    "auditeur": frozenset({"verifier_chaine", "expirations"}),
}
